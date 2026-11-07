package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"

	"github.com/wuling/xdp-forward-panel/internal/version"
)

type Config struct {
	ListenAddr   string  `json:"listen_addr"`
	ListenPort   int     `json:"listen_port"`
	BasePath     string  `json:"base_path"`
	DataDir      string  `json:"data_dir"`
	Iface        string  `json:"iface"`
	PublicHost  string `json:"public_host"` // domain or IP for TLS SAN / hints
	TLSMode     string `json:"tls_mode"`    // selfsigned | letsencrypt | zerossl
	ACMEEmail   string `json:"acme_email"`
	SNATPortMin uint16 `json:"snat_port_min"`
	SNATPortMax uint16 `json:"snat_port_max"`
	TLSCertFile string `json:"tls_cert_file"`
	TLSKeyFile  string `json:"tls_key_file"`
	UpdateURL   string `json:"update_url"`
	AutoUpdate  bool   `json:"auto_update"`
	TGToken      string  `json:"tg_token"`
	TGAdminIDs   []int64 `json:"tg_admin_ids"`
	TGEnabled    bool    `json:"tg_enabled"`
	XDPMode      string  `json:"xdp_mode"` // auto|native|generic
	CsumSafe     bool    `json:"csum_safe"` // true → BPF full TCP recompute (slower, virtio-safe)
	CsumFast     bool    `json:"csum_fast,omitempty"` // legacy; ignored if csum_safe set via UI
	PanelVersion string  `json:"-"`
	BPFVersion   string  `json:"-"`
}

func Default(dataDir string) *Config {
	return &Config{
		ListenAddr:  "0.0.0.0",
		ListenPort:  2888,
		BasePath:    "/",
		DataDir:     dataDir,
		Iface:       "",
		PublicHost:  "",
		TLSMode:     "selfsigned",
		ACMEEmail:   "",
		SNATPortMin: 40000,
		SNATPortMax: 49999,
		TLSCertFile: filepath.Join(dataDir, "tls", "cert.pem"),
		TLSKeyFile:  filepath.Join(dataDir, "tls", "key.pem"),
		UpdateURL:   "https://github.com/gzjacktang/xdpforward/releases/latest",
		AutoUpdate:  true,
		TGAdminIDs:  nil,
		TGEnabled:   false,
		XDPMode:     "auto",
		PanelVersion: version.Version,
		BPFVersion:   version.BPFVersion,
	}
}

type Manager struct {
	mu   sync.RWMutex
	path string
	cfg  *Config
}

func LoadOrCreate(path string, dataDir string) (*Manager, error) {
	m := &Manager{path: path, cfg: Default(dataDir)}
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				return nil, err
			}
			return m, m.Save()
		}
		return nil, err
	}
	if err := json.Unmarshal(b, m.cfg); err != nil {
		return nil, err
	}
	if m.cfg.DataDir == "" {
		m.cfg.DataDir = dataDir
	}
	if m.cfg.SNATPortMin == 0 {
		m.cfg.SNATPortMin = 40000
	}
	if m.cfg.SNATPortMax == 0 {
		m.cfg.SNATPortMax = 49999
	}
	if m.cfg.ListenPort == 0 {
		m.cfg.ListenPort = 2888
	}
	m.cfg.PanelVersion = version.Version
	m.cfg.BPFVersion = version.BPFVersion
	return m, nil
}

func (m *Manager) Get() Config {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return *m.cfg
}

func (m *Manager) Update(fn func(*Config)) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	fn(m.cfg)
	return m.saveLocked()
}

func (m *Manager) Save() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.saveLocked()
}

func (m *Manager) saveLocked() error {
	b, err := json.MarshalIndent(m.cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(m.path, b, 0o600)
}
