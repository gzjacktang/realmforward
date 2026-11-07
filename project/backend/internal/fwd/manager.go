package fwd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
)

const (
	nftFamily = "ip"
	nftTable  = "nftfp"
)

type Manager struct {
	mu     sync.Mutex
	status Status
	rules  []Rule
}

func New() *Manager {
	return &Manager{}
}

func (m *Manager) Status() Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.status
}

func (m *Manager) Load(iface string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if iface == "" {
		return fmt.Errorf("iface required")
	}
	if _, err := net.InterfaceByName(iface); err != nil {
		return fmt.Errorf("iface %s: %w", iface, err)
	}
	if _, err := exec.LookPath("nft"); err != nil {
		return fmt.Errorf("nft not found: install nftables")
	}

	if err := ensureIPForward(); err != nil {
		m.status = Status{Loaded: false, Iface: iface, Error: err.Error()}
		return err
	}
	if err := ensureTable(); err != nil {
		m.status = Status{Loaded: false, Iface: iface, Error: err.Error()}
		return err
	}

	m.status = Status{
		Loaded: true,
		Mode:   "nftables",
		Iface:  iface,
	}
	return nil
}

func (m *Manager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	// Leave nft rules in place across restarts so traffic keeps flowing during brief downtime.
	// Fresh SyncRules on next Load replaces content. Uninstall scripts delete the table.
	m.status.Loaded = false
	return nil
}

func (m *Manager) SyncRules(rules []Rule) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.status.Loaded {
		return fmt.Errorf("forward engine not loaded")
	}
	iface := m.status.Iface

	var b strings.Builder
	b.WriteString(fmt.Sprintf("flush chain %s %s prerouting\n", nftFamily, nftTable))
	b.WriteString(fmt.Sprintf("flush chain %s %s postrouting\n", nftFamily, nftTable))
	b.WriteString(fmt.Sprintf("flush chain %s %s forward\n", nftFamily, nftTable))

	// Allow established/related always.
	b.WriteString(fmt.Sprintf(
		"add rule %s %s forward ct state established,related accept comment \"nftfp-est\"\n",
		nftFamily, nftTable))

	enabled := 0
	for _, r := range rules {
		if !r.Enabled {
			continue
		}
		protos, err := ExpandProtoNames(r.Proto)
		if err != nil {
			return err
		}
		ip := net.ParseIP(r.DestIP)
		if ip == nil || ip.To4() == nil {
			return fmt.Errorf("IPv4 only: %s", r.DestIP)
		}
		dest := fmt.Sprintf("%s:%d", r.DestIP, r.DestPort)
		for _, proto := range protos {
			cmt := fmt.Sprintf("nftfp-r%d-%s", r.ID, proto)
			// DNAT
			b.WriteString(fmt.Sprintf(
				"add rule %s %s prerouting iifname %q %s dport %d counter dnat to %s comment %q\n",
				nftFamily, nftTable, iface, proto, r.LocalPort, dest, cmt))
			// FORWARD accept new flows to dest
			b.WriteString(fmt.Sprintf(
				"add rule %s %s forward oifname != \"lo\" %s dport %d ip daddr %s counter accept comment %q\n",
				nftFamily, nftTable, proto, r.DestPort, r.DestIP, cmt+"-fwd"))
			// Masquerade replies path / outbound after DNAT
			b.WriteString(fmt.Sprintf(
				"add rule %s %s postrouting oifname %q %s dport %d ip daddr %s counter masquerade comment %q\n",
				nftFamily, nftTable, iface, proto, r.DestPort, r.DestIP, cmt+"-snat"))
		}
		enabled++
	}

	if err := nftApply(b.String()); err != nil {
		return err
	}
	m.rules = append([]Rule(nil), rules...)
	m.status.RuleCount = enabled
	return nil
}

func (m *Manager) GetStats() map[uint32]Stats {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[uint32]Stats)
	if !m.status.Loaded {
		return out
	}
	raw, err := exec.Command("nft", "-j", "list", "chain", nftFamily, nftTable, "prerouting").CombinedOutput()
	if err != nil {
		return out
	}
	var doc struct {
		Nftables []json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return out
	}
	for _, item := range doc.Nftables {
		var wrap struct {
			Rule *struct {
				Comment string `json:"comment"`
				Counter *struct {
					Packets uint64 `json:"packets"`
					Bytes   uint64 `json:"bytes"`
				} `json:"counter"`
			} `json:"rule"`
		}
		if err := json.Unmarshal(item, &wrap); err != nil || wrap.Rule == nil || wrap.Rule.Counter == nil {
			continue
		}
		id, ok := parseRuleID(wrap.Rule.Comment)
		if !ok {
			continue
		}
		st := out[id]
		st.Packets += wrap.Rule.Counter.Packets
		st.Bytes += wrap.Rule.Counter.Bytes
		out[id] = st
	}
	return out
}

// ApplyRuntimeConfig is kept for API compatibility; nft engine has no csum/SNAT pool.
func (m *Manager) ApplyRuntimeConfig(iface string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if iface != "" {
		if _, err := net.InterfaceByName(iface); err != nil {
			return fmt.Errorf("iface %s: %w", iface, err)
		}
		m.status.Iface = iface
	}
	return nil
}

func parseRuleID(comment string) (uint32, bool) {
	// nftfp-r12-tcp
	if !strings.HasPrefix(comment, "nftfp-r") {
		return 0, false
	}
	rest := strings.TrimPrefix(comment, "nftfp-r")
	i := strings.IndexByte(rest, '-')
	if i <= 0 {
		return 0, false
	}
	n, err := strconv.ParseUint(rest[:i], 10, 32)
	if err != nil {
		return 0, false
	}
	return uint32(n), true
}

func ensureIPForward() error {
	if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1\n"), 0o644); err != nil {
		return fmt.Errorf("enable ip_forward: %w", err)
	}
	return nil
}

func ensureTable() error {
	if out, err := exec.Command("nft", "list", "table", nftFamily, nftTable).CombinedOutput(); err != nil || len(out) == 0 {
		if err := nftApply(fmt.Sprintf("add table %s %s\n", nftFamily, nftTable)); err != nil {
			return err
		}
	}
	chains := []struct {
		name string
		def  string
	}{
		{"prerouting", "{ type nat hook prerouting priority dstnat; policy accept; }"},
		{"postrouting", "{ type nat hook postrouting priority srcnat; policy accept; }"},
		{"forward", "{ type filter hook forward priority filter; policy accept; }"},
	}
	for _, c := range chains {
		if _, err := exec.Command("nft", "list", "chain", nftFamily, nftTable, c.name).CombinedOutput(); err != nil {
			script := fmt.Sprintf("add chain %s %s %s %s\n", nftFamily, nftTable, c.name, c.def)
			if err := nftApply(script); err != nil {
				return err
			}
		}
	}
	return nil
}

func nftApply(script string) error {
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("nft: %v: %s", err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

// DeleteTable removes the panel nft table (used by uninstall).
func DeleteTable() error {
	return nftApply(fmt.Sprintf("delete table %s %s\n", nftFamily, nftTable))
}
