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

const maxRuleKeys = 256

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
	iface    string

	prevGRO     string // "on" / "off" / ""
	prevRxGROHW string
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
	CsumMode uint8 // 0=fast incremental, 1=safe full TCP recompute
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

func ethtoolFeature(iface, name string) string {
	out, err := exec.Command("ethtool", "-k", iface).CombinedOutput()
	if err != nil {
		return ""
	}
	prefix := name + ":"
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, prefix) {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				return strings.TrimSuffix(fields[1], "[fixed]")
			}
		}
	}
	return ""
}

func (m *Manager) disableGRO(iface string) {
	m.prevGRO = ethtoolFeature(iface, "generic-receive-offload")
	m.prevRxGROHW = ethtoolFeature(iface, "rx-gro-hw")
	var notes []string
	if err := exec.Command("ethtool", "-K", iface, "gro", "off").Run(); err != nil {
		notes = append(notes, "ethtool gro off: "+err.Error())
	}
	if err := exec.Command("ethtool", "-K", iface, "rx-gro-hw", "off").Run(); err != nil {
		notes = append(notes, "ethtool rx-gro-hw off: "+err.Error())
	}
	if len(notes) > 0 {
		m.status.Error = strings.TrimSpace(m.status.Error + " " + strings.Join(notes, "; "))
	}
}

func (m *Manager) restoreGRO() {
	if m.iface == "" {
		return
	}
	if m.prevGRO == "on" {
		_ = exec.Command("ethtool", "-K", m.iface, "gro", "on").Run()
	}
	if m.prevRxGROHW == "on" {
		_ = exec.Command("ethtool", "-K", m.iface, "rx-gro-hw", "on").Run()
	}
}

func (m *Manager) writeConfig(cfg configVal) error {
	if m.cfgMap == nil {
		return fmt.Errorf("config map not loaded")
	}
	var key uint32
	if err := m.cfgMap.Put(key, cfg); err != nil {
		return fmt.Errorf("config map put: %w", err)
	}
	return nil
}

func (m *Manager) putGatewayLocked(iface string, cfg *configVal) {
	if gw, local, ok := resolveEgressMACs(iface); ok {
		cfg.GwMAC = gw
		cfg.LocalMAC = local
		cfg.HasGw = 1
	} else {
		cfg.HasGw = 0
		cfg.GwMAC = [6]byte{}
	}
}

func (m *Manager) Load(iface string, mode string, snatMin, snatMax uint16, csumMode uint8) error {
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

	m.iface = iface
	m.status = Status{Iface: iface}
	m.disableGRO(iface)

	usedMode, l, err := attachXDP(prog, ifi.Index, mode)
	if err != nil {
		m.restoreGRO()
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

	if csumMode > 1 {
		csumMode = 1 // treat unknown as safe
	}
	cfg := configVal{Ifindex: uint32(ifi.Index), SNATMin: snatMin, SNATMax: snatMax, CsumMode: csumMode}
	m.putGatewayLocked(iface, &cfg)
	if err := m.writeConfig(cfg); err != nil {
		_ = m.closeLocked()
		m.status = Status{Loaded: false, Iface: iface, Error: err.Error()}
		return err
	}
	if err := applyReservedPorts(snatMin, snatMax); err != nil {
		m.status.Error = strings.TrimSpace(m.status.Error + " reserved ports: " + err.Error())
	}

	m.status.Loaded = true
	m.status.Mode = usedMode
	m.status.SNATMin = snatMin
	m.status.SNATMax = snatMax
	m.status.CsumMode = csumMode
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
	if err := m.cfgMap.Lookup(key, &cfg); err != nil {
		return
	}
	m.putGatewayLocked(m.status.Iface, &cfg)
	_ = m.cfgMap.Put(key, cfg)
	if cfg.HasGw == 0 {
		m.status.Error = strings.TrimSpace(strings.ReplaceAll(m.status.Error, "gateway MAC unresolved", "") + " gateway MAC unresolved")
	} else {
		m.status.Error = strings.TrimSpace(strings.ReplaceAll(m.status.Error, "gateway MAC unresolved", ""))
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
	m.restoreGRO()
	m.rulesMap, m.statsMap, m.cfgMap, m.ctMap = nil, nil, nil, nil
	m.status.Loaded = false
	return nil
}

func countRuleKeys(rules []Rule) (int, error) {
	n := 0
	for _, r := range rules {
		protos, err := ExpandProtos(r.Proto)
		if err != nil {
			return 0, err
		}
		n += len(protos)
	}
	return n, nil
}

func (m *Manager) SyncRules(rules []Rule) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.rulesMap == nil {
		return fmt.Errorf("XDP not loaded")
	}
	nkeys, err := countRuleKeys(rules)
	if err != nil {
		return err
	}
	if nkeys > maxRuleKeys {
		return fmt.Errorf("too many rule keys (%d); max %d (proto=both counts as 2)", nkeys, maxRuleKeys)
	}

	// Validate all entries before mutating the map.
	type pending struct {
		key ruleKey
		val ruleVal
	}
	var want []pending
	activeIDs := map[uint32]struct{}{}
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
		activeIDs[r.ID] = struct{}{}
		for _, pn := range protos {
			want = append(want, pending{
				key: ruleKey{Dport: r.LocalPort, Proto: pn},
				val: ruleVal{
					RuleID:   r.ID,
					DestIP:   binary.BigEndian.Uint32(ip4),
					DestPort: r.DestPort,
					Enabled:  en,
				},
			})
		}
	}

	iter := m.rulesMap.Iterate()
	var k ruleKey
	var v ruleVal
	var oldKeys []ruleKey
	for iter.Next(&k, &v) {
		oldKeys = append(oldKeys, k)
	}
	for _, kk := range oldKeys {
		_ = m.rulesMap.Delete(kk)
	}
	for _, p := range want {
		if err := m.rulesMap.Put(p.key, p.val); err != nil {
			return fmt.Errorf("rule put %d/%d: %w", p.key.Dport, p.key.Proto, err)
		}
	}
	m.status.RuleCount = len(rules)

	// Drop orphan stats keys (per-CPU hash).
	if m.statsMap != nil {
		siter := m.statsMap.Iterate()
		var sid uint32
		var perCPU []statsVal
		var drop []uint32
		for siter.Next(&sid, &perCPU) {
			if _, ok := activeIDs[sid]; !ok {
				drop = append(drop, sid)
			}
		}
		for _, id := range drop {
			_ = m.statsMap.Delete(id)
		}
	}

	if m.cfgMap != nil {
		var key uint32
		var cfg configVal
		_ = m.cfgMap.Lookup(key, &cfg)
		m.putGatewayLocked(m.status.Iface, &cfg)
		if err := m.cfgMap.Put(key, cfg); err != nil {
			return fmt.Errorf("gateway config: %w", err)
		}
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
	var perCPU []statsVal
	for iter.Next(&id, &perCPU) {
		var sum Stats
		for _, v := range perCPU {
			sum.Packets += v.Packets
			sum.Bytes += v.Bytes
		}
		out[id] = sum
	}
	return out
}

func (m *Manager) ApplyReservedPorts(snatMin, snatMax uint16) error {
	return applyReservedPorts(snatMin, snatMax)
}

// ApplyRuntimeConfig updates SNAT range + csum_mode in the live BPF config map.
func (m *Manager) ApplyRuntimeConfig(snatMin, snatMax uint16, csumMode uint8) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if csumMode > 1 {
		csumMode = 1
	}
	if m.cfgMap == nil {
		return fmt.Errorf("XDP config map not loaded")
	}
	var key uint32
	var cfg configVal
	if err := m.cfgMap.Lookup(key, &cfg); err != nil {
		return fmt.Errorf("config lookup: %w", err)
	}
	cfg.SNATMin = snatMin
	cfg.SNATMax = snatMax
	cfg.CsumMode = csumMode
	if err := m.cfgMap.Put(key, cfg); err != nil {
		return fmt.Errorf("config put: %w", err)
	}
	m.status.SNATMin = snatMin
	m.status.SNATMax = snatMax
	m.status.CsumMode = csumMode
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
