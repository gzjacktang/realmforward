package firewall

import (
	"fmt"
	"os"
	"os/exec"
	"regexp"
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

// nftChain is the real input filter chain we mutate (e.g. inet/filter/input).
type nftChain struct {
	Family string // inet | ip | ip6
	Table  string // filter, …
	Chain  string // input, INPUT, …
}

type Manager struct {
	Backend Backend
	nft     *nftChain // set when BackendNftables
}

func Detect() *Manager {
	if out, err := exec.Command("ufw", "status").CombinedOutput(); err == nil {
		if strings.Contains(string(out), "Status: active") {
			return &Manager{Backend: BackendUFW}
		}
	}
	if _, err := exec.LookPath("nft"); err == nil {
		if ch := discoverNftInput(); ch != nil {
			return &Manager{Backend: BackendNftables, nft: ch}
		}
		// nft present but no input hook yet — still prefer nft over legacy iptables-nft shim
		if err := exec.Command("nft", "list", "ruleset").Run(); err == nil {
			return &Manager{Backend: BackendNftables, nft: &nftChain{Family: "inet", Table: "filter", Chain: "input"}}
		}
	}
	if _, err := exec.LookPath("iptables"); err == nil {
		return &Manager{Backend: BackendIptables}
	}
	return &Manager{Backend: BackendNone}
}

var (
	reNftTable = regexp.MustCompile(`(?m)^table\s+(inet|ip|ip6)\s+(\S+)\s*\{`)
	reNftChain = regexp.MustCompile(`(?m)^\s*chain\s+(\S+)\s*\{`)
	reNftHook  = regexp.MustCompile(`\btype\s+filter\b.*\bhook\s+input\b`)
	reNftDport = regexp.MustCompile(`\b(tcp|udp)\s+dport\s+(\d+)\b`)
	reNftSet   = regexp.MustCompile(`\b(tcp|udp)\s+dport\s+\{([^}]+)\}`)
)

// discoverNftInput finds the filter/input chain that actually drops/accepts traffic.
// Prefer inet filter input, then any inet * input, then ip filter INPUT.
func discoverNftInput() *nftChain {
	out, err := exec.Command("nft", "-a", "list", "ruleset").CombinedOutput()
	if err != nil {
		return nil
	}
	text := string(out)
	type cand struct {
		ch       nftChain
		priority int // lower = better
	}
	var cands []cand
	family, table := "", ""
	lines := strings.Split(text, "\n")
	for i, line := range lines {
		if m := reNftTable.FindStringSubmatch(line); m != nil {
			family, table = m[1], m[2]
			continue
		}
		if m := reNftChain.FindStringSubmatch(line); m != nil && family != "" {
			chain := m[1]
			// look ahead a few lines for hook input
			window := line
			for j := i + 1; j < len(lines) && j <= i+6; j++ {
				window += " " + lines[j]
				if strings.Contains(lines[j], "}") && !strings.Contains(lines[j], "{") {
					break
				}
			}
			if !reNftHook.MatchString(window) {
				continue
			}
			ch := nftChain{Family: family, Table: table, Chain: chain}
			prio := 100
			if family == "inet" && table == "filter" && strings.EqualFold(chain, "input") {
				prio = 0
			} else if family == "inet" && strings.EqualFold(chain, "input") {
				prio = 10
			} else if family == "ip" && table == "filter" {
				prio = 20
			} else if family == "inet" {
				prio = 30
			}
			cands = append(cands, cand{ch: ch, priority: prio})
		}
	}
	if len(cands) == 0 {
		return nil
	}
	best := cands[0]
	for _, c := range cands[1:] {
		if c.priority < best.priority {
			best = c
		}
	}
	return &best.ch
}

func (m *Manager) ensureNft() *nftChain {
	if m.nft != nil {
		return m.nft
	}
	if ch := discoverNftInput(); ch != nil {
		m.nft = ch
		return ch
	}
	m.nft = &nftChain{Family: "inet", Table: "filter", Chain: "input"}
	return m.nft
}

func (m *Manager) nftRef() string {
	ch := m.ensureNft()
	return fmt.Sprintf("%s %s %s", ch.Family, ch.Table, ch.Chain)
}

// NftChain returns "family table chain" for UI/debug, or empty if not nft.
func (m *Manager) NftChain() string {
	if m.Backend != BackendNftables {
		return ""
	}
	return m.nftRef()
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
		ch := m.ensureNft()
		out, err := exec.Command("nft", "list", "chain", ch.Family, ch.Table, ch.Chain).CombinedOutput()
		if err != nil {
			return false
		}
		s := strings.ToLower(string(out))
		return strings.Contains(s, "policy drop") || strings.Contains(s, "policy drop;")
	default:
		return false
	}
}

// EnsureBaseRules installs lo + ESTABLISHED accepts needed before a DROP policy.
func (m *Manager) EnsureBaseRules() error {
	switch m.Backend {
	case BackendUFW:
		return nil
	case BackendIptables:
		_ = ensureIptables("-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT")
		_ = ensureIptables("-i", "lo", "-j", "ACCEPT")
		return nil
	case BackendNftables:
		return m.ensureNftBase()
	default:
		return fmt.Errorf("no firewall backend detected")
	}
}

func (m *Manager) ensureNftBase() error {
	ch := m.ensureNft()
	_ = run("nft", "add", "table", ch.Family, ch.Table)
	// ensure chain exists (keep existing policy if already there)
	_ = run("nft", "add", "chain", ch.Family, ch.Table, ch.Chain,
		"{", "type", "filter", "hook", "input", "priority", "0", ";", "policy", "drop", ";", "}")

	out, _ := exec.Command("nft", "list", "chain", ch.Family, ch.Table, ch.Chain).CombinedOutput()
	s := string(out)
	if !strings.Contains(s, "established") {
		_ = run("nft", "insert", "rule", ch.Family, ch.Table, ch.Chain,
			"ct", "state", "established,related", "accept")
	}
	if !strings.Contains(s, `iif "lo"`) && !strings.Contains(s, "iif lo") && !strings.Contains(s, `iifname "lo"`) {
		_ = run("nft", "insert", "rule", ch.Family, ch.Table, ch.Chain, "iif", "lo", "accept")
	}
	return nil
}

func ensureIptables(args ...string) error {
	checkArgs := append([]string{"-C", "INPUT"}, args...)
	if exec.Command("iptables", checkArgs...).Run() == nil {
		return nil
	}
	insArgs := append([]string{"-I", "INPUT"}, args...)
	return run("iptables", insArgs...)
}

// EnableDenyIncoming turns on default-deny inbound on the *existing* backend.
// Do NOT switch a live nftables host onto ufw just because the binary exists.
func (m *Manager) EnableDenyIncoming() error {
	switch m.Backend {
	case BackendUFW:
		_ = run("ufw", "default", "deny", "incoming")
		_ = run("ufw", "default", "allow", "outgoing")
		return run("ufw", "--force", "enable")
	case BackendIptables:
		if err := m.EnsureBaseRules(); err != nil {
			return err
		}
		return run("iptables", "-P", "INPUT", "DROP")
	case BackendNftables:
		ch := m.ensureNft()
		if err := m.ensureNftBase(); err != nil {
			return err
		}
		// Force policy drop on the real input chain without wiping host rules:
		// delete+recreate only if policy is not already drop.
		out, _ := exec.Command("nft", "list", "chain", ch.Family, ch.Table, ch.Chain).CombinedOutput()
		if strings.Contains(strings.ToLower(string(out)), "policy drop") {
			return nil
		}
		// nft can't change policy in-place portably; add a jump table is riskier.
		// Recreate chain: save accept dport rules, recreate with drop, restore + base.
		ports := listNftChain(ch)
		_ = run("nft", "delete", "chain", ch.Family, ch.Table, ch.Chain)
		if err := run("nft", "add", "chain", ch.Family, ch.Table, ch.Chain,
			"{", "type", "filter", "hook", "input", "priority", "0", ";", "policy", "drop", ";", "}"); err != nil {
			return err
		}
		_ = m.ensureNftBase()
		for _, p := range ports {
			_ = m.openNft(p.Port, p.Proto)
		}
		return nil
	case BackendNone:
		// last resort: create inet filter if nft exists
		if _, err := exec.LookPath("nft"); err == nil {
			m.Backend = BackendNftables
			m.nft = &nftChain{Family: "inet", Table: "filter", Chain: "input"}
			return m.EnableDenyIncoming()
		}
		if _, err := exec.LookPath("ufw"); err == nil {
			m.Backend = BackendUFW
			return m.EnableDenyIncoming()
		}
		return fmt.Errorf("no firewall backend detected")
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
	_ = m.persist()
	return last
}

func (m *Manager) openOne(port int, proto string) error {
	switch m.Backend {
	case BackendUFW:
		return run("ufw", "allow", fmt.Sprintf("%d/%s", port, proto))
	case BackendNftables:
		return m.openNft(port, proto)
	case BackendIptables:
		return m.openIptables(port, proto)
	case BackendNone:
		return fmt.Errorf("no firewall backend detected")
	}
	return nil
}

func (m *Manager) openNft(port int, proto string) error {
	ch := m.ensureNft()
	_ = m.ensureNftBase()
	if m.nftHasAccept(ch, port, proto) {
		return nil
	}
	comment := fmt.Sprintf("nftfp-%d-%s", port, proto)
	return run("nft", "add", "rule", ch.Family, ch.Table, ch.Chain,
		proto, "dport", strconv.Itoa(port), "accept", "comment", comment)
}

func (m *Manager) nftHasAccept(ch *nftChain, port int, proto string) bool {
	for _, p := range listNftChain(ch) {
		if p.Port == port && p.Proto == proto {
			return true
		}
	}
	return false
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
	_ = m.persist()
	return nil
}

func (m *Manager) closeOne(port int, proto string) error {
	switch m.Backend {
	case BackendUFW:
		return run("ufw", "delete", "allow", fmt.Sprintf("%d/%s", port, proto))
	case BackendNftables:
		return m.closeNft(port, proto)
	case BackendIptables:
		for {
			if exec.Command("iptables", "-C", "INPUT", "-p", proto, "--dport", strconv.Itoa(port), "-j", "ACCEPT").Run() != nil {
				break
			}
			_ = run("iptables", "-D", "INPUT", "-p", proto, "--dport", strconv.Itoa(port), "-j", "ACCEPT")
		}
		return nil
	case BackendNone:
		return fmt.Errorf("no firewall backend detected")
	}
	return nil
}

func (m *Manager) closeNft(port int, proto string) error {
	ch := m.ensureNft()
	out, err := exec.Command("nft", "-a", "list", "chain", ch.Family, ch.Table, ch.Chain).CombinedOutput()
	if err != nil {
		return nil
	}
	var handles []string
	var restore []int
	seenRestore := map[int]bool{}
	for _, line := range strings.Split(string(out), "\n") {
		if !strings.Contains(line, "accept") {
			continue
		}
		// set form first: tcp dport { 80, 443, 14444 }
		if sm := reNftSet.FindStringSubmatch(line); sm != nil && sm[1] == proto {
			if csvHasPort(sm[2], port) {
				if h := nftHandle(line); h != "" {
					handles = append(handles, h)
				}
				// Deleting the whole set would close siblings — re-open the rest.
				for _, p := range portsExcept(sm[2], port) {
					if !seenRestore[p] {
						seenRestore[p] = true
						restore = append(restore, p)
					}
				}
			}
			continue
		}
		if dm := reNftDport.FindStringSubmatch(line); dm != nil && dm[1] == proto {
			p, _ := strconv.Atoi(dm[2])
			if p == port {
				if h := nftHandle(line); h != "" {
					handles = append(handles, h)
				}
			}
		}
	}
	for _, h := range handles {
		_ = run("nft", "delete", "rule", ch.Family, ch.Table, ch.Chain, "handle", h)
	}
	for _, p := range restore {
		_ = m.openNft(p, proto)
	}
	return nil
}

func nftHandle(line string) string {
	fields := strings.Fields(line)
	for i, f := range fields {
		if f == "handle" && i+1 < len(fields) {
			return fields[i+1]
		}
	}
	return ""
}

func csvHasPort(csv string, port int) bool {
	for _, part := range strings.Split(csv, ",") {
		part = strings.TrimSpace(part)
		if part == strconv.Itoa(port) {
			return true
		}
	}
	return false
}

// portsExcept parses an nft dport set CSV and returns ports other than exclude.
func portsExcept(csv string, exclude int) []int {
	var out []int
	for _, part := range strings.Split(csv, ",") {
		part = strings.TrimSpace(part)
		p, err := strconv.Atoi(part)
		if err != nil || p <= 0 || p == exclude {
			continue
		}
		out = append(out, p)
	}
	return out
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
		return listNftChain(m.ensureNft())
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

func listNftChain(ch *nftChain) []OpenPort {
	if ch == nil {
		return nil
	}
	out, err := exec.Command("nft", "list", "chain", ch.Family, ch.Table, ch.Chain).CombinedOutput()
	if err != nil {
		return nil
	}
	seen := map[string]OpenPort{}
	add := func(proto string, port int) {
		if port <= 0 {
			return
		}
		k := fmt.Sprintf("%s/%d", proto, port)
		seen[k] = OpenPort{Port: port, Proto: proto}
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if !strings.Contains(line, "accept") {
			continue
		}
		if m := reNftSet.FindStringSubmatch(line); m != nil {
			proto := m[1]
			for _, part := range strings.Split(m[2], ",") {
				part = strings.TrimSpace(part)
				p, err := strconv.Atoi(part)
				if err == nil {
					add(proto, p)
				}
			}
			continue
		}
		if m := reNftDport.FindStringSubmatch(line); m != nil {
			p, _ := strconv.Atoi(m[2])
			add(m[1], p)
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

// persist writes the live nftables ruleset back to /etc/nftables.conf when it
// already looks like a full ruleset file (avoid clobbering include-only configs).
func (m *Manager) persist() error {
	if m.Backend != BackendNftables {
		return nil
	}
	path := "/etc/nftables.conf"
	prev, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	ps := string(prev)
	if !strings.Contains(ps, "flush ruleset") && !strings.Contains(ps, "table inet filter") && !strings.Contains(ps, "table ip filter") {
		return nil
	}
	out, err := exec.Command("nft", "list", "ruleset").CombinedOutput()
	if err != nil {
		return err
	}
	body := "#!/usr/sbin/nft -f\nflush ruleset\n" + string(out)
	return os.WriteFile(path, []byte(body), 0644)
}

func run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %v: %v (%s)", name, args, err, strings.TrimSpace(string(out)))
	}
	return nil
}
