//go:build !linux

package xdp

import "fmt"

type Manager struct {
	status Status
	rules  map[uint32]Rule
	stats  map[uint32]Stats
}

func New() *Manager {
	return &Manager{
		rules: make(map[uint32]Rule),
		stats: make(map[uint32]Stats),
		status: Status{Loaded: false, Mode: "", Error: "XDP only supported on Linux"},
	}
}

func (m *Manager) SetObjectPath(string) {}

func (m *Manager) Status() Status { return m.status }

func (m *Manager) Load(iface string, mode string, snatMin, snatMax uint16, csumMode uint8) error {
	m.status = Status{
		Loaded: false, Mode: "", Iface: iface, SNATMin: snatMin, SNATMax: snatMax, CsumMode: csumMode,
		Error: "XDP load requires Linux (build and run on Debian/Ubuntu VPS)",
	}
	return fmt.Errorf("%s", m.status.Error)
}

func (m *Manager) Close() error { return nil }

func (m *Manager) SyncRules(rules []Rule) error {
	m.rules = make(map[uint32]Rule, len(rules))
	for _, r := range rules {
		m.rules[r.ID] = r
	}
	m.status.RuleCount = len(rules)
	return nil
}

func (m *Manager) GetStats() map[uint32]Stats {
	out := make(map[uint32]Stats, len(m.stats))
	for k, v := range m.stats {
		out[k] = v
	}
	return out
}

func (m *Manager) ApplyReservedPorts(snatMin, snatMax uint16) error {
	return nil
}

func (m *Manager) ApplyRuntimeConfig(snatMin, snatMax uint16, csumMode uint8) error {
	m.status.SNATMin = snatMin
	m.status.SNATMax = snatMax
	m.status.CsumMode = csumMode
	return nil
}

func (m *Manager) RefreshGateway() {}
