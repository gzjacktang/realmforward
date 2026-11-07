package fwd

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

type Manager struct {
	mu         sync.Mutex
	status     Status
	rules      []Rule
	dataDir    string
	realmBin   string
	configPath string
	cmd        *exec.Cmd
	logFile    *os.File
}

func New() *Manager {
	return &Manager{}
}

func (m *Manager) Status() Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	st := m.status
	if st.Loaded && m.cmd != nil && m.cmd.Process != nil {
		if err := m.cmd.Process.Signal(syscall.Signal(0)); err != nil {
			st.Error = "realm process not running"
			st.Loaded = false
		}
	}
	return st
}

// SetDataDir sets where realm.json and logs live (call before Load).
func (m *Manager) SetDataDir(dir string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.dataDir = dir
}

// SetRealmBin overrides realm binary path (optional).
func (m *Manager) SetRealmBin(path string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.realmBin = path
}

func (m *Manager) Load(iface string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.dataDir == "" {
		m.dataDir = "/var/lib/realmfp"
	}
	if err := os.MkdirAll(m.dataDir, 0o755); err != nil {
		return err
	}
	// Drop leftover nftables table from older panel versions.
	_ = exec.Command("nft", "delete", "table", "ip", "realmfp").Run()

	bin, err := resolveRealmBin(m.realmBin)
	if err != nil {
		m.status = Status{Loaded: false, Iface: iface, Error: err.Error()}
		return err
	}
	m.realmBin = bin
	m.configPath = filepath.Join(m.dataDir, "realm.json")

	if iface != "" {
		if _, err := net.InterfaceByName(iface); err != nil {
			return fmt.Errorf("iface %s: %w", iface, err)
		}
	}

	if err := writeRealmConfig(m.configPath, iface, nil); err != nil {
		m.status = Status{Loaded: false, Iface: iface, Error: err.Error()}
		return err
	}
	// Process starts on SyncRules (empty endpoint list may exit immediately).
	m.status = Status{Loaded: true, Mode: "realm", Iface: iface}
	return nil
}

func (m *Manager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stopLocked()
	m.status.Loaded = false
	return nil
}

func (m *Manager) SyncRules(rules []Rule) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.status.Loaded && m.cmd == nil {
		return fmt.Errorf("forward engine not loaded")
	}
	iface := m.status.Iface
	if err := writeRealmConfig(m.configPath, iface, rules); err != nil {
		return err
	}
	enabled := 0
	for _, r := range rules {
		if r.Enabled {
			enabled++
		}
	}
	m.stopLocked()
	if enabled > 0 {
		if err := m.startLocked(); err != nil {
			m.status.Error = err.Error()
			m.status.Loaded = false
			return err
		}
	}
	m.rules = append([]Rule(nil), rules...)
	m.status.Loaded = true
	m.status.Mode = "realm"
	m.status.RuleCount = enabled
	m.status.Error = ""
	return nil
}

func (m *Manager) GetStats() map[uint32]Stats {
	// Realm has no byte counters. Expose active TCP connection count as Packets
	// (UI labels it 连接); Bytes stays 0 → frontend shows "—".
	m.mu.Lock()
	rules := append([]Rule(nil), m.rules...)
	m.mu.Unlock()
	out := make(map[uint32]Stats, len(rules))
	for _, r := range rules {
		if !r.Enabled || r.LocalPort <= 0 {
			continue
		}
		out[uint32(r.ID)] = Stats{Packets: countActiveConns(int(r.LocalPort)), Bytes: 0}
	}
	return out
}

func countActiveConns(port int) uint64 {
	// Established TCP peers on the listen port (Realm accepted connections).
	out, err := exec.Command("ss", "-Htan", "state", "established", fmt.Sprintf("( sport = :%d )", port)).Output()
	if err != nil || len(out) == 0 {
		return 0
	}
	var n uint64
	for _, line := range strings.Split(string(out), "\n") {
		if strings.TrimSpace(line) != "" {
			n++
		}
	}
	return n
}

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

func (m *Manager) startLocked() error {
	if m.realmBin == "" || m.configPath == "" {
		return fmt.Errorf("realm not configured")
	}
	logPath := filepath.Join(m.dataDir, "realm.log")
	cmd := exec.Command(m.realmBin, "-c", m.configPath)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644); err == nil {
		m.logFile = f
		cmd.Stdout = f
		cmd.Stderr = f
	}
	if err := cmd.Start(); err != nil {
		if m.logFile != nil {
			_ = m.logFile.Close()
			m.logFile = nil
		}
		return fmt.Errorf("start realm: %w", err)
	}
	m.cmd = cmd
	// Brief health check
	time.Sleep(150 * time.Millisecond)
	if err := cmd.Process.Signal(syscall.Signal(0)); err != nil {
		return fmt.Errorf("realm exited immediately; check %s", logPath)
	}
	go func(c *exec.Cmd) {
		_ = c.Wait()
	}(cmd)
	return nil
}

func (m *Manager) stopLocked() {
	if m.cmd == nil || m.cmd.Process == nil {
		m.cmd = nil
		return
	}
	pgid := m.cmd.Process.Pid
	_ = syscall.Kill(-pgid, syscall.SIGTERM)
	done := make(chan struct{})
	go func() {
		_, _ = m.cmd.Process.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		_ = syscall.Kill(-pgid, syscall.SIGKILL)
	}
	m.cmd = nil
	if m.logFile != nil {
		_ = m.logFile.Close()
		m.logFile = nil
	}
}

type realmFile struct {
	Log      realmLog        `json:"log"`
	Network  realmNetwork    `json:"network"`
	Endpoints []realmEndpoint `json:"endpoints"`
}

type realmLog struct {
	Level  string `json:"level"`
	Output string `json:"output"`
}

type realmNetwork struct {
	NoTCP  bool `json:"no_tcp"`
	UseUDP bool `json:"use_udp"`
}

type realmEndpoint struct {
	Listen          string       `json:"listen"`
	Remote          string       `json:"remote"`
	Interface       string       `json:"interface,omitempty"`
	ListenInterface string       `json:"listen_interface,omitempty"`
	Network         *realmNetwork `json:"network,omitempty"`
}

func writeRealmConfig(path, iface string, rules []Rule) error {
	cfg := realmFile{
		Log: realmLog{Level: "warn", Output: "stdout"},
		Network: realmNetwork{
			NoTCP:  false,
			UseUDP: false, // per-endpoint overrides
		},
		Endpoints: []realmEndpoint{},
	}
	for _, r := range rules {
		if !r.Enabled {
			continue
		}
		ip := net.ParseIP(r.DestIP)
		if ip == nil || ip.To4() == nil {
			return fmt.Errorf("IPv4 only: %s", r.DestIP)
		}
		protos, err := ExpandProtoNames(r.Proto)
		if err != nil {
			return err
		}
		useTCP, useUDP := false, false
		for _, p := range protos {
			if p == "tcp" {
				useTCP = true
			}
			if p == "udp" {
				useUDP = true
			}
		}
		ep := realmEndpoint{
			Listen: fmt.Sprintf("0.0.0.0:%d", r.LocalPort),
			Remote: fmt.Sprintf("%s:%d", r.DestIP, r.DestPort),
			Network: &realmNetwork{
				NoTCP:  !useTCP,
				UseUDP: useUDP,
			},
		}
		if iface != "" {
			ep.Interface = iface
			ep.ListenInterface = iface
		}
		cfg.Endpoints = append(cfg.Endpoints, ep)
	}
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}

func resolveRealmBin(override string) (string, error) {
	candidates := []string{}
	if override != "" {
		candidates = append(candidates, override)
	}
	if exe, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Join(filepath.Dir(exe), "realm"))
	}
	candidates = append(candidates,
		"/usr/lib/realmfp/realm",
		"/usr/local/bin/realm",
		"realm",
	)
	for _, c := range candidates {
		if c == "realm" {
			if p, err := exec.LookPath("realm"); err == nil {
				return p, nil
			}
			continue
		}
		if st, err := os.Stat(c); err == nil && !st.IsDir() {
			return c, nil
		}
	}
	return "", fmt.Errorf("realm binary not found (install to /usr/lib/realmfp/realm or PATH)")
}
