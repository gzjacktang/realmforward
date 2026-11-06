package firewall

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

type Backend string

const (
	BackendUFW      Backend = "ufw"
	BackendNftables Backend = "nftables"
	BackendIptables Backend = "iptables"
	BackendNone     Backend = "none"
)

type Manager struct {
	Backend Backend
}

func Detect() *Manager {
	if out, err := exec.Command("ufw", "status").CombinedOutput(); err == nil {
		if strings.Contains(string(out), "Status: active") {
			return &Manager{Backend: BackendUFW}
		}
	}
	if _, err := exec.LookPath("nft"); err == nil {
		if err := exec.Command("nft", "list", "ruleset").Run(); err == nil {
			return &Manager{Backend: BackendNftables}
		}
	}
	if _, err := exec.LookPath("iptables"); err == nil {
		return &Manager{Backend: BackendIptables}
	}
	return &Manager{Backend: BackendNone}
}

func expandFWProtos(proto string) []string {
	switch strings.ToLower(proto) {
	case "both", "tcp+udp", "all":
		return []string{"tcp", "udp"}
	default:
		return []string{strings.ToLower(proto)}
	}
}

func (m *Manager) Open(port int, proto string) error {
	var last error
	for _, p := range expandFWProtos(proto) {
		if err := m.openOne(port, p); err != nil {
			last = err
		}
	}
	return last
}

func (m *Manager) openOne(port int, proto string) error {
	switch m.Backend {
	case BackendUFW:
		return run("ufw", "allow", fmt.Sprintf("%d/%s", port, proto))
	case BackendNftables:
		_ = run("nft", "add", "table", "inet", "xfp")
		_ = run("nft", "add", "chain", "inet", "xfp", "input", "{", "type", "filter", "hook", "input", "priority", "0", ";", "policy", "accept", ";", "}")
		return run("nft", "add", "rule", "inet", "xfp", "input", proto, "dport", strconv.Itoa(port), "accept", "comment", fmt.Sprintf("xfp-%d", port))
	case BackendIptables:
		return m.openIptables(port, proto)
	case BackendNone:
		return fmt.Errorf("no firewall backend detected")
	}
	return nil
}

func (m *Manager) openIptables(port int, proto string) error {
	check := exec.Command("iptables", "-C", "INPUT", "-p", proto, "--dport", strconv.Itoa(port), "-j", "ACCEPT")
	if check.Run() == nil {
		return nil
	}
	return run("iptables", "-I", "INPUT", "-p", proto, "--dport", strconv.Itoa(port), "-j", "ACCEPT")
}

func (m *Manager) Close(port int, proto string) error {
	for _, p := range expandFWProtos(proto) {
		_ = m.closeOne(port, p)
	}
	return nil
}

func (m *Manager) closeOne(port int, proto string) error {
	switch m.Backend {
	case BackendUFW:
		return run("ufw", "delete", "allow", fmt.Sprintf("%d/%s", port, proto))
	case BackendNftables:
		out, err := exec.Command("nft", "-a", "list", "chain", "inet", "xfp", "input").CombinedOutput()
		if err != nil {
			return nil
		}
		needle := fmt.Sprintf("dport %d", port)
		for _, line := range strings.Split(string(out), "\n") {
			if strings.Contains(line, needle) && strings.Contains(line, proto) {
				fields := strings.Fields(line)
				for i, f := range fields {
					if f == "handle" && i+1 < len(fields) {
						_ = run("nft", "delete", "rule", "inet", "xfp", "input", "handle", fields[i+1])
					}
				}
			}
		}
		return nil
	case BackendIptables:
		_ = run("iptables", "-D", "INPUT", "-p", proto, "--dport", strconv.Itoa(port), "-j", "ACCEPT")
		return nil
	case BackendNone:
		return fmt.Errorf("no firewall backend detected")
	}
	return nil
}

type OpenPort struct {
	Port  int
	Proto string
}

// ListOpen returns ports currently allowed by the active firewall backend.
func (m *Manager) ListOpen() []OpenPort {
	switch m.Backend {
	case BackendUFW:
		return listUFW()
	case BackendNftables:
		return listNft()
	case BackendIptables:
		return listIptables()
	default:
		return nil
	}
}

func listUFW() []OpenPort {
	out, err := exec.Command("ufw", "status").CombinedOutput()
	if err != nil {
		return nil
	}
	seen := map[string]OpenPort{}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Status:") || strings.HasPrefix(line, "To") || strings.HasPrefix(line, "--") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 || !strings.EqualFold(fields[1], "ALLOW") {
			continue
		}
		port, proto, ok := parsePortProto(fields[0])
		if !ok {
			continue
		}
		k := fmt.Sprintf("%s/%d", proto, port)
		seen[k] = OpenPort{Port: port, Proto: proto}
	}
	res := make([]OpenPort, 0, len(seen))
	for _, v := range seen {
		res = append(res, v)
	}
	return res
}

func listNft() []OpenPort {
	out, err := exec.Command("nft", "list", "ruleset").CombinedOutput()
	if err != nil {
		return nil
	}
	seen := map[string]OpenPort{}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		proto := ""
		if strings.Contains(line, "tcp dport") {
			proto = "tcp"
		} else if strings.Contains(line, "udp dport") {
			proto = "udp"
		} else {
			continue
		}
		if !strings.Contains(line, "accept") {
			continue
		}
		fields := strings.Fields(line)
		for i, f := range fields {
			if f == "dport" && i+1 < len(fields) {
				p, err := strconv.Atoi(fields[i+1])
				if err == nil && p > 0 {
					k := fmt.Sprintf("%s/%d", proto, p)
					seen[k] = OpenPort{Port: p, Proto: proto}
				}
			}
		}
	}
	res := make([]OpenPort, 0, len(seen))
	for _, v := range seen {
		res = append(res, v)
	}
	return res
}

func listIptables() []OpenPort {
	out, err := exec.Command("iptables", "-L", "INPUT", "-n").CombinedOutput()
	if err != nil {
		return nil
	}
	seen := map[string]OpenPort{}
	for _, line := range strings.Split(string(out), "\n") {
		if !strings.Contains(line, "ACCEPT") || !strings.Contains(line, "dpt:") {
			continue
		}
		proto := "tcp"
		fields := strings.Fields(line)
		if len(fields) > 0 {
			p := strings.ToLower(fields[0])
			if p == "udp" || p == "tcp" {
				proto = p
			}
		}
		idx := strings.Index(line, "dpt:")
		if idx < 0 {
			continue
		}
		rest := line[idx+4:]
		num := ""
		for _, ch := range rest {
			if ch >= '0' && ch <= '9' {
				num += string(ch)
			} else {
				break
			}
		}
		p, err := strconv.Atoi(num)
		if err != nil || p <= 0 {
			continue
		}
		k := fmt.Sprintf("%s/%d", proto, p)
		seen[k] = OpenPort{Port: p, Proto: proto}
	}
	res := make([]OpenPort, 0, len(seen))
	for _, v := range seen {
		res = append(res, v)
	}
	return res
}

func parsePortProto(s string) (port int, proto string, ok bool) {
	s = strings.TrimSpace(s)
	// 50123/tcp or 50123/tcp (v6)
	s = strings.Split(s, " ")[0]
	parts := strings.Split(s, "/")
	if len(parts) != 2 {
		return 0, "", false
	}
	p, err := strconv.Atoi(parts[0])
	if err != nil || p <= 0 {
		return 0, "", false
	}
	proto = strings.ToLower(parts[1])
	if proto != "tcp" && proto != "udp" {
		return 0, "", false
	}
	return p, proto, true
}

// IsOpen best-effort check
func (m *Manager) IsOpen(port int, proto string) bool {
	open := map[string]bool{}
	for _, p := range m.ListOpen() {
		if p.Port == port {
			open[p.Proto] = true
		}
	}
	for _, p := range expandFWProtos(proto) {
		if !open[p] {
			return false
		}
	}
	return true
}

func run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %v: %v (%s)", name, args, err, strings.TrimSpace(string(out)))
	}
	return nil
}
