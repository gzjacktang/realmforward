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

// Active reports whether a deny-by-default firewall is in effect (best-effort).
func (m *Manager) Active() bool {
	switch m.Backend {
	case BackendUFW:
		out, err := exec.Command("ufw", "status").CombinedOutput()
		return err == nil && strings.Contains(string(out), "Status: active")
	case BackendIptables:
		out, err := exec.Command("iptables", "-L", "INPUT", "-n").CombinedOutput()
		if err != nil {
			return false
		}
		for _, line := range strings.Split(string(out), "\n") {
			if strings.HasPrefix(line, "Chain INPUT") && strings.Contains(line, "policy DROP") {
				return true
			}
		}
		return false
	case BackendNftables:
		out, err := exec.Command("nft", "list", "chain", "inet", "xfp", "input").CombinedOutput()
		return err == nil && strings.Contains(string(out), "policy drop")
	default:
		return false
	}
}

// EnsureBaseRules installs lo + ESTABLISHED accepts needed before a DROP policy.
func (m *Manager) EnsureBaseRules() error {
	switch m.Backend {
	case BackendUFW:
		return nil // ufw manages this
	case BackendIptables:
		_ = ensureIptables("-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT")
		_ = ensureIptables("-i", "lo", "-j", "ACCEPT")
		return nil
	case BackendNftables:
		_ = run("nft", "add", "table", "inet", "xfp")
		_ = run("nft", "add", "chain", "inet", "xfp", "input", "{", "type", "filter", "hook", "input", "priority", "0", ";", "policy", "accept", ";", "}")
		out, _ := exec.Command("nft", "list", "chain", "inet", "xfp", "input").CombinedOutput()
		s := string(out)
		if !strings.Contains(s, "ct state established") && !strings.Contains(s, "ct state { established") {
			_ = run("nft", "insert", "rule", "inet", "xfp", "input", "ct", "state", "established,related", "accept")
		}
		if !strings.Contains(s, "iif \"lo\"") && !strings.Contains(s, "iifname \"lo\"") {
			_ = run("nft", "insert", "rule", "inet", "xfp", "input", "iif", "lo", "accept")
		}
		return nil
	default:
		return fmt.Errorf("no firewall backend detected")
	}
}

func ensureIptables(args ...string) error {
	checkArgs := append([]string{"-C", "INPUT"}, args...)
	if exec.Command("iptables", checkArgs...).Run() == nil {
		return nil
	}
	insArgs := append([]string{"-I", "INPUT"}, args...)
	return run("iptables", insArgs...)
}

// EnableDenyIncoming turns on default-deny inbound.
// Prefer ufw when installed (even if previously inactive).
func (m *Manager) EnableDenyIncoming() error {
	if _, err := exec.LookPath("ufw"); err == nil {
		m.Backend = BackendUFW
		_ = run("ufw", "default", "deny", "incoming")
		_ = run("ufw", "default", "allow", "outgoing")
		if err := run("ufw", "--force", "enable"); err != nil {
			return err
		}
		return nil
	}
	if err := m.EnsureBaseRules(); err != nil {
		return err
	}
	switch m.Backend {
	case BackendIptables:
		return run("iptables", "-P", "INPUT", "DROP")
	case BackendNftables:
		_ = run("nft", "add", "table", "inet", "xfp")
		_ = run("nft", "delete", "chain", "inet", "xfp", "input")
		if err := run("nft", "add", "chain", "inet", "xfp", "input", "{", "type", "filter", "hook", "input", "priority", "0", ";", "policy", "drop", ";", "}"); err != nil {
			return err
		}
		return m.EnsureBaseRules()
	case BackendUFW:
		_ = run("ufw", "default", "deny", "incoming")
		return run("ufw", "--force", "enable")
	default:
		return fmt.Errorf("no firewall backend detected")
	}
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
