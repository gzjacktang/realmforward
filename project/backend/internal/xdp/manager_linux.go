//go:build linux

package xdp

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

type Manager struct {
	mu       sync.Mutex
	coll     *ebpf.Collection
	link     link.Link
	status   Status
	objPath  string
	rulesMap *ebpf.Map
	statsMap *ebpf.Map
	cfgMap   *ebpf.Map
	ctMap    *ebpf.Map
}

type ruleKey struct {
	Dport uint16
	Proto uint8
	Pad   uint8
}

type ruleVal struct {
	RuleID   uint32
	DestIP   uint32
	DestPort uint16
	Enabled  uint8
	Pad      uint8
}

type statsVal struct {
	Packets uint64
	Bytes   uint64
}

type configVal struct {
	Ifindex  uint32
	LocalIP  uint32
	SNATMin  uint16
	SNATMax  uint16
	GwMAC    [6]byte
	LocalMAC [6]byte
	HasGw    uint8
	Pad      uint8
}

func New() *Manager {
	return &Manager{status: Status{Loaded: false}}
}

func (m *Manager) SetObjectPath(p string) { m.objPath = p }

func (m *Manager) Status() Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.status
}

func (m *Manager) Load(iface string, mode string, snatMin, snatMax uint16) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	_ = m.closeLocked()

	obj := m.objPath
	if obj == "" {
		obj = defaultObjectPath()
	}
	spec, err := ebpf.LoadCollectionSpec(obj)
	if err != nil {
		m.status = Status{Loaded: false, Iface: iface, Error: fmt.Sprintf("load BPF ELF: %v", err)}
		return fmt.Errorf("%s", m.status.Error)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		m.status = Status{Loaded: false, Iface: iface, Error: fmt.Sprintf("create collection: %v", err)}
		return fmt.Errorf("%s", m.status.Error)
	}

	prog := coll.Programs["xdp_forward"]
	if prog == nil {
		coll.Close()
		m.status = Status{Loaded: false, Iface: iface, Error: "program xdp_forward not found"}
		return fmt.Errorf("%s", m.status.Error)
	}

	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		coll.Close()
		m.status = Status{Loaded: false, Iface: iface, Error: err.Error()}
		return err
	}

	// virtio/KVM: GRO/GSO can leave mangled L4 checksums that break XDP NAT incremental updates
	_ = exec.Command("ethtool", "-K", iface, "gro", "off").Run()
	_ = exec.Command("ethtool", "-K", iface, "gso", "off").Run()
	_ = exec.Command("ethtool", "-K", iface, "tso", "off").Run()
	_ = exec.Command("ethtool", "-K", iface, "rx-gro-hw", "off").Run()
	_ = exec.Command("ethtool", "-K", iface, "rx", "off").Run()

	usedMode, l, err := attachXDP(prog, ifi.Index, mode)
	if err != nil {
		coll.Close()
		m.status = Status{Loaded: false, Iface: iface, Error: err.Error()}
		return err
	}

	m.coll = coll
	m.link = l
	m.rulesMap = coll.Maps["rules"]
	m.statsMap = coll.Maps["stats"]
	m.cfgMap = coll.Maps["config"]
	m.ctMap = coll.Maps["conntrack"]

	cfg := configVal{Ifindex: uint32(ifi.Index), SNATMin: snatMin, SNATMax: snatMax}
	if gw, local, ok := resolveEgressMACs(iface); ok {
		cfg.GwMAC = gw
		cfg.LocalMAC = local
		cfg.HasGw = 1
	}
	var key uint32
	if m.cfgMap != nil {
		_ = m.cfgMap.Put(key, cfg)
	}
	if err := applyReservedPorts(snatMin, snatMax); err != nil {
		m.status.Error = "reserved ports: " + err.Error()
	}

	m.status = Status{
		Loaded: true, Mode: usedMode, Iface: iface,
		SNATMin: snatMin, SNATMax: snatMax,
	}
	if cfg.HasGw == 0 {
		m.status.Error = strings.TrimSpace(m.status.Error + " gateway MAC unresolved")
	}
	return nil
}

func (m *Manager) RefreshGateway() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cfgMap == nil || m.status.Iface == "" {
		return
	}
	var key uint32
	var cfg configVal
	_ = m.cfgMap.Lookup(key, &cfg)
	if gw, local, ok := resolveEgressMACs(m.status.Iface); ok {
		cfg.GwMAC = gw
		cfg.LocalMAC = local
		cfg.HasGw = 1
		_ = m.cfgMap.Put(key, cfg)
	}
}

func attachXDP(prog *ebpf.Program, ifindex int, mode string) (string, link.Link, error) {
	mode = strings.ToLower(mode)
	try := func(flags link.XDPAttachFlags, name string) (link.Link, error) {
		return link.AttachXDP(link.XDPOptions{Program: prog, Interface: ifindex, Flags: flags})
	}
	switch mode {
	case "native":
		l, err := try(link.XDPDriverMode, "native")
		return "native", l, err
	case "generic":
		l, err := try(link.XDPGenericMode, "generic")
		return "generic", l, err
	default:
		l, err := try(link.XDPDriverMode, "native")
		if err == nil {
			return "native", l, nil
		}
		l2, err2 := try(link.XDPGenericMode, "generic")
		if err2 != nil {
			return "", nil, fmt.Errorf("native failed: %v; generic failed: %v", err, err2)
		}
		return "generic", l2, nil
	}
}

func (m *Manager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.closeLocked()
}

func (m *Manager) closeLocked() error {
	if m.link != nil {
		_ = m.link.Close()
		m.link = nil
	}
	if m.coll != nil {
		m.coll.Close()
		m.coll = nil
	}
	m.rulesMap, m.statsMap, m.cfgMap, m.ctMap = nil, nil, nil, nil
	m.status.Loaded = false
	return nil
}

func (m *Manager) SyncRules(rules []Rule) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.rulesMap == nil {
		return fmt.Errorf("XDP not loaded")
	}
	// clear by iterating — replace: delete all known then add
	iter := m.rulesMap.Iterate()
	var k ruleKey
	var v ruleVal
	var keys []ruleKey
	for iter.Next(&k, &v) {
		keys = append(keys, k)
	}
	for _, kk := range keys {
		_ = m.rulesMap.Delete(kk)
	}
	for _, r := range rules {
		protos, err := ExpandProtos(r.Proto)
		if err != nil {
			return err
		}
		ip := net.ParseIP(r.DestIP)
		if ip == nil {
			return fmt.Errorf("bad dest ip %s", r.DestIP)
		}
		ip4 := ip.To4()
		if ip4 == nil {
			return fmt.Errorf("IPv4 only: %s", r.DestIP)
		}
		en := uint8(0)
		if r.Enabled {
			en = 1
		}
		for _, pn := range protos {
			key := ruleKey{Dport: r.LocalPort, Proto: pn}
			val := ruleVal{
				RuleID:   r.ID,
				DestIP:   binary.BigEndian.Uint32(ip4),
				DestPort: r.DestPort,
				Enabled:  en,
			}
			if err := m.rulesMap.Put(key, val); err != nil {
				return err
			}
		}
	}
	m.status.RuleCount = len(rules)
	// refresh gateway MAC each sync (neigh may appear later)
	if gw, local, ok := resolveEgressMACs(m.status.Iface); ok && m.cfgMap != nil {
		var key uint32
		var cfg configVal
		_ = m.cfgMap.Lookup(key, &cfg)
		cfg.GwMAC = gw
		cfg.LocalMAC = local
		cfg.HasGw = 1
		_ = m.cfgMap.Put(key, cfg)
	}
	return nil
}

func (m *Manager) GetStats() map[uint32]Stats {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[uint32]Stats)
	if m.statsMap == nil {
		return out
	}
	iter := m.statsMap.Iterate()
	var id uint32
	var st statsVal
	for iter.Next(&id, &st) {
		out[id] = Stats{Packets: st.Packets, Bytes: st.Bytes}
	}
	return out
}

func (m *Manager) ApplyReservedPorts(snatMin, snatMax uint16) error {
	return applyReservedPorts(snatMin, snatMax)
}

func applyReservedPorts(snatMin, snatMax uint16) error {
	path := "/proc/sys/net/ipv4/ip_local_reserved_ports"
	val := fmt.Sprintf("%d-%d", snatMin, snatMax)
	return os.WriteFile(path, []byte(val), 0o644)
}

func defaultObjectPath() string {
	candidates := []string{
		"bpf/xdp_forward.o",
		"/usr/lib/xdp-forward-panel/xdp_forward.o",
		filepath.Join(filepath.Dir(os.Args[0]), "xdp_forward.o"),
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	return candidates[0]
}
