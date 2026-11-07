package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gzjacktang/realmforward/internal/auth"
	"github.com/gzjacktang/realmforward/internal/config"
	"github.com/gzjacktang/realmforward/internal/firewall"
	"github.com/gzjacktang/realmforward/internal/listen"
	"github.com/gzjacktang/realmforward/internal/store"
	"github.com/gzjacktang/realmforward/internal/tlsutil"
	"github.com/gzjacktang/realmforward/internal/fwd"
)

type Server struct {
	Cfg      *config.Manager
	Store    *store.Store
	Auth     *auth.Service
	Fwd     *fwd.Manager
	FW       *firewall.Manager
	Static   fs.FS
	SSHPort  int
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	cfg := s.Cfg.Get()
	base := strings.TrimSuffix(cfg.BasePath, "/")
	if base == "" {
		base = ""
	}
	api := func(p string) string {
		if base == "" {
			return "/api" + p
		}
		return base + "/api" + p
	}

	mux.HandleFunc(api("/login"), s.handleLogin)
	mux.HandleFunc(api("/logout"), s.requireAuth(s.handleLogout))
	mux.HandleFunc(api("/status"), s.requireAuth(s.handleStatus))
	mux.HandleFunc(api("/forwards"), s.requireAuth(s.handleForwards))
	mux.HandleFunc(api("/forwards/"), s.requireAuth(s.handleForwardItem))
	mux.HandleFunc(api("/ports"), s.requireAuth(s.handlePorts))
	mux.HandleFunc(api("/ports/open"), s.requireAuth(s.handlePortOpen))
	mux.HandleFunc(api("/ports/close"), s.requireAuth(s.handlePortClose))
	mux.HandleFunc(api("/ports/harden"), s.requireAuth(s.handlePortsHarden))
	mux.HandleFunc(api("/tg"), s.requireAuth(s.handleTG))
	mux.HandleFunc(api("/logs"), s.requireAuth(s.handleLogs))
	mux.HandleFunc(api("/settings"), s.requireAuth(s.handleSettings))
	mux.HandleFunc(api("/settings/account"), s.requireAuth(s.handleAccount))
	mux.HandleFunc(api("/settings/tls/regen"), s.requireAuth(s.handleTLSRegen))
	mux.HandleFunc(api("/settings/tls/issue"), s.requireAuth(s.handleTLSIssue))
	mux.HandleFunc(api("/settings/restart"), s.requireAuth(s.handleRestart))
	mux.HandleFunc(api("/settings/update"), s.requireAuth(s.handleUpdate))
	mux.HandleFunc(api("/settings/update/status"), s.requireAuth(s.handleUpdateStatus))
	mux.HandleFunc(api("/settings/uninstall"), s.requireAuth(s.handleUninstall))

	// static under base path
	if s.Static != nil {
		staticPrefix := base + "/"
		if base == "" {
			staticPrefix = "/"
		}
		mux.Handle(staticPrefix, s.staticHandler(base))
	}
	// if custom base_path, redirect bare / to it
	if base != "" {
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/" || r.URL.Path == "" {
				http.Redirect(w, r, base+"/", http.StatusFound)
				return
			}
			http.NotFound(w, r)
		})
	}
	return mux
}

func (s *Server) staticHandler(base string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		if base != "" {
			p = strings.TrimPrefix(p, base)
		}
		if p == "" || p == "/" {
			p = "/index.html"
		}
		p = strings.TrimPrefix(path.Clean(p), "/")
		b, err := fs.ReadFile(s.Static, p)
		if err != nil {
			b, err = fs.ReadFile(s.Static, "index.html")
			if err != nil {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write(injectBase(b, base))
			return
		}
		if p == "index.html" {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write(injectBase(b, base))
			return
		}
		http.ServeContent(w, r, p, time.Time{}, bytes.NewReader(b))
	})
}

func injectBase(html []byte, base string) []byte {
	snippet := []byte(`<script>window.XFP_BASE=` + strconv.Quote(base) + `;</script>`)
	if i := bytes.Index(html, []byte("<head>")); i >= 0 {
		i += len("<head>")
		out := make([]byte, 0, len(html)+len(snippet))
		out = append(out, html[:i]...)
		out = append(out, snippet...)
		out = append(out, html[i:]...)
		return out
	}
	return append(snippet, html...)
}

func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(auth.CookieName)
		if err != nil || !s.Auth.Valid(c.Value) {
			writeErr(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		next(w, r)
	}
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method")
		return
	}
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, 400, "bad json")
		return
	}
	token, err := s.Auth.Login(body.Username, body.Password)
	if err != nil {
		_ = s.Store.AddAudit("web", body.Username, "auth.login", "fail", err.Error())
		writeErr(w, 401, "invalid credentials")
		return
	}
	path := "/"
	if bp := strings.TrimSuffix(s.Cfg.Get().BasePath, "/"); bp != "" {
		path = bp + "/"
	}
	http.SetCookie(w, &http.Cookie{
		Name:     auth.CookieName,
		Value:    token,
		Path:     path,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   true,
		Expires:  time.Now().Add(auth.SessionTTL),
	})
	_ = s.Store.AddAudit("web", body.Username, "auth.login", "ok", "")
	writeJSON(w, map[string]any{"ok": true, "token": token})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(auth.CookieName); err == nil {
		_ = s.Auth.Logout(c.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: auth.CookieName, Value: "", Path: "/", MaxAge: -1})
	writeJSON(w, map[string]any{"ok": true})
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	cfg := s.Cfg.Get()
	xs := s.Fwd.Status()
	writeJSON(w, map[string]any{
		"panel_version":  cfg.PanelVersion,
		"engine_version": cfg.EngineVer,
		"fwd":            xs,
		"firewall":       s.FW.Backend,
		"listen":         fmt.Sprintf("%s:%d", cfg.ListenAddr, cfg.ListenPort),
		"base_path":      cfg.BasePath,
		"tg_enabled":     cfg.TGEnabled,
		"warning":        "经 Realm 用户态转发（splice 零拷贝）；改网卡后需重启面板。",
	})
}

func (s *Server) handleForwards(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		rules, err := s.Store.ListForwards()
		if err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		st := s.Fwd.GetStats()
		for i := range rules {
			if s, ok := st[uint32(rules[i].ID)]; ok {
				rules[i].Packets = s.Packets
				rules[i].Bytes = s.Bytes
			}
		}
		writeJSON(w, rules)
	case http.MethodPost:
		var body struct {
			LocalPort int    `json:"local_port"`
			DestIP    string `json:"dest_ip"`
			DestPort  int    `json:"dest_port"`
			Proto     string `json:"proto"`
			Note      string `json:"note"`
			Enabled   *bool  `json:"enabled"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeErr(w, 400, "bad json")
			return
		}
		en := true
		if body.Enabled != nil {
			en = *body.Enabled
		}
		if net.ParseIP(body.DestIP).To4() == nil {
			writeErr(w, 400, "IPv4 only")
			return
		}
		proto, err := fwd.NormalizeProto(body.Proto)
		if err != nil {
			writeErr(w, 400, err.Error())
			return
		}
		id, err := s.Store.AddForward(body.LocalPort, body.DestIP, body.DestPort, proto, body.Note, en)
		if err != nil {
			writeErr(w, 400, err.Error())
			return
		}
		_ = s.FW.Open(body.LocalPort, proto)
		if err := s.syncFwd(); err != nil {
			writeErr(w, 500, "saved but fwd sync: "+err.Error())
			return
		}
		_ = s.Store.AddAudit("web", "admin", "fwd.add", "ok", fmt.Sprintf("%d %d->%s:%d %s", id, body.LocalPort, body.DestIP, body.DestPort, proto))
		writeJSON(w, map[string]any{"id": id})
	default:
		writeErr(w, 405, "method")
	}
}

func (s *Server) handleForwardItem(w http.ResponseWriter, r *http.Request) {
	cfg := s.Cfg.Get()
	prefix := strings.TrimSuffix(cfg.BasePath, "/") + "/api/forwards/"
	if strings.TrimSuffix(cfg.BasePath, "/") == "" {
		prefix = "/api/forwards/"
	}
	idStr := strings.TrimPrefix(r.URL.Path, prefix)
	idStr = strings.Trim(idStr, "/")
	parts := strings.Split(idStr, "/")
	id, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		writeErr(w, 400, "bad id")
		return
	}
	if len(parts) == 2 && parts[1] == "enable" && r.Method == http.MethodPost {
		var body struct {
			Enabled bool `json:"enabled"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if err := s.Store.UpdateForwardEnabled(id, body.Enabled); err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		_ = s.syncFwd()
		writeJSON(w, map[string]any{"ok": true})
		return
	}
	if (r.Method == http.MethodPut || r.Method == http.MethodPost) && len(parts) == 1 {
		var body struct {
			LocalPort int    `json:"local_port"`
			DestIP    string `json:"dest_ip"`
			DestPort  int    `json:"dest_port"`
			Proto     string `json:"proto"`
			Note      string `json:"note"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeErr(w, 400, "bad json")
			return
		}
		if net.ParseIP(body.DestIP).To4() == nil {
			writeErr(w, 400, "IPv4 only")
			return
		}
		proto, err := fwd.NormalizeProto(body.Proto)
		if err != nil {
			writeErr(w, 400, err.Error())
			return
		}
		old, _ := s.Store.GetForward(id)
		if err := s.Store.UpdateForward(id, body.LocalPort, body.DestIP, body.DestPort, proto, body.Note); err != nil {
			writeErr(w, 400, err.Error())
			return
		}
		if old != nil && (old.LocalPort != body.LocalPort || old.Proto != proto) {
			_ = s.FW.Close(old.LocalPort, old.Proto)
		}
		_ = s.FW.Open(body.LocalPort, proto)
		_ = s.syncFwd()
		_ = s.Store.AddAudit("web", "admin", "fwd.edit", "ok", fmt.Sprintf("%d", id))
		writeJSON(w, map[string]any{"ok": true})
		return
	}
	if r.Method == http.MethodDelete {
		if fr, err := s.Store.GetForward(id); err == nil {
			_ = s.FW.Close(fr.LocalPort, fr.Proto)
		}
		if err := s.Store.DeleteForward(id); err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		_ = s.syncFwd()
		_ = s.Store.AddAudit("web", "admin", "fwd.del", "ok", fmt.Sprintf("%d", id))
		writeJSON(w, map[string]any{"ok": true})
		return
	}
	writeErr(w, 405, "method")
}

func (s *Server) handlePorts(w http.ResponseWriter, r *http.Request) {
	type row struct {
		Port      int    `json:"port"`
		Proto     string `json:"proto"`
		Firewall  string `json:"firewall"`
		Listening string `json:"listening"`
		Fwd       string `json:"fwd"`
		Protected bool   `json:"protected"`
	}
	cfg := s.Cfg.Get()
	rules, _ := s.Store.ListForwards()
	listenSnap := listen.Snapshot()
	listenMap := map[string]listen.Entry{}
	for _, e := range listenSnap {
		listenMap[fmt.Sprintf("%s/%d", e.Proto, e.Port)] = e
	}
	seen := map[string]row{}
	var add func(port int, proto string)
	add = func(port int, proto string) {
		proto = strings.ToLower(proto)
		if proto == "both" || proto == "tcp+udp" || proto == "all" {
			add(port, "tcp")
			add(port, "udp")
			return
		}
		k := fmt.Sprintf("%s/%d", proto, port)
		if _, ok := seen[k]; ok {
			return
		}
		fw := "closed"
		if s.FW.IsOpen(port, proto) {
			fw = "open"
		}
		lis := "无"
		if e, ok := listenMap[k]; ok {
			if e.Process != "" {
				lis = e.Process
			} else {
				lis = "listening"
			}
		}
		fwdTag := "—"
		for _, fr := range rules {
			if !fr.Enabled || fr.LocalPort != port {
				continue
			}
			fp := strings.ToLower(fr.Proto)
			if fp == proto || fp == "both" || fp == "tcp+udp" {
				fwdTag = fmt.Sprintf("fwd #%d", fr.ID)
				break
			}
		}
		prot := port == cfg.ListenPort || (s.SSHPort > 0 && port == s.SSHPort)
		seen[k] = row{Port: port, Proto: proto, Firewall: fw, Listening: lis, Fwd: fwdTag, Protected: prot}
	}
	add(cfg.ListenPort, "tcp")
	if s.SSHPort > 0 {
		add(s.SSHPort, "tcp")
	}
	for _, e := range listenSnap {
		add(e.Port, e.Proto)
	}
	for _, fr := range rules {
		add(fr.LocalPort, fr.Proto)
	}
	for _, op := range s.FW.ListOpen() {
		add(op.Port, op.Proto)
	}

	// merge same port tcp+udp into one proto=both row
	byPort := map[int][]row{}
	for _, v := range seen {
		hasBiz := v.Listening != "无" || v.Fwd != "—" || v.Protected
		if v.Firewall == "closed" && !hasBiz {
			continue
		}
		byPort[v.Port] = append(byPort[v.Port], v)
	}
	out := make([]row, 0, len(seen))
	for _, rows := range byPort {
		var tcp, udp *row
		for i := range rows {
			switch rows[i].Proto {
			case "tcp":
				tcp = &rows[i]
			case "udp":
				udp = &rows[i]
			}
		}
		if tcp != nil && udp != nil {
			merged := *tcp
			merged.Proto = "both"
			switch {
			case tcp.Firewall == "open" && udp.Firewall == "open":
				merged.Firewall = "open"
			case tcp.Firewall == "open" || udp.Firewall == "open":
				merged.Firewall = "partial"
			default:
				merged.Firewall = "closed"
			}
			if merged.Listening == "无" && udp.Listening != "无" {
				merged.Listening = udp.Listening
			}
			if merged.Fwd == "—" && udp.Fwd != "—" {
				merged.Fwd = udp.Fwd
			}
			merged.Protected = tcp.Protected || udp.Protected
			out = append(out, merged)
			continue
		}
		if tcp != nil {
			out = append(out, *tcp)
		}
		if udp != nil {
			out = append(out, *udp)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Port == out[j].Port {
			return out[i].Proto < out[j].Proto
		}
		return out[i].Port < out[j].Port
	})
	resp := map[string]any{
		"backend":   s.FW.Backend,
		"ports":     out,
		"ssh_port":  s.SSHPort,
		"page_size": 20,
		"fw_active": s.FW.Active(),
	}
	if s.FW.Backend == firewall.BackendNftables {
		resp["nft_chain"] = s.FW.NftChain()
	}
	writeJSON(w, resp)
}

// handlePortsHarden enables default-deny firewall and closes ports with no
// business (no listener, no nft forward, not SSH/panel). Keeps business ports open.
func (s *Server) handlePortsHarden(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, 405, "method")
		return
	}
	cfg := s.Cfg.Get()
	rules, _ := s.Store.ListForwards()
	listenSnap := listen.Snapshot()

	type keepKey struct {
		port  int
		proto string
	}
	keep := map[keepKey]string{} // reason
	var addKeep func(port int, proto, reason string)
	addKeep = func(port int, proto, reason string) {
		proto = strings.ToLower(proto)
		if proto == "both" || proto == "tcp+udp" || proto == "all" {
			addKeep(port, "tcp", reason)
			addKeep(port, "udp", reason)
			return
		}
		if port <= 0 {
			return
		}
		keep[keepKey{port, proto}] = reason
	}
	addKeep(cfg.ListenPort, "tcp", "panel")
	if s.SSHPort > 0 {
		addKeep(s.SSHPort, "tcp", "ssh")
	}
	for _, e := range listenSnap {
		addKeep(e.Port, e.Proto, "listen")
	}
	for _, fr := range rules {
		if !fr.Enabled {
			continue
		}
		addKeep(fr.LocalPort, fr.Proto, "fwd")
	}

	// Open business ports first (before DROP policy).
	var opened []string
	for k, reason := range keep {
		if err := s.FW.Open(k.port, k.proto); err != nil {
			writeErr(w, 500, fmt.Sprintf("放行 %d/%s 失败: %v", k.port, k.proto, err))
			return
		}
		opened = append(opened, fmt.Sprintf("%d/%s(%s)", k.port, k.proto, reason))
	}

	// Close firewall allows that are not business.
	var closed []string
	for _, op := range s.FW.ListOpen() {
		if _, ok := keep[keepKey{op.Port, op.Proto}]; ok {
			continue
		}
		_ = s.FW.Close(op.Port, op.Proto)
		closed = append(closed, fmt.Sprintf("%d/%s", op.Port, op.Proto))
	}
	// Re-open keep immediately: closing a nft set rule may have removed kept ports too.
	for k := range keep {
		_ = s.FW.Open(k.port, k.proto)
	}

	if err := s.FW.EnsureBaseRules(); err != nil {
		writeErr(w, 500, "基础规则失败: "+err.Error())
		return
	}
	if err := s.FW.EnableDenyIncoming(); err != nil {
		writeErr(w, 500, "开启防火墙失败: "+err.Error())
		return
	}
	// Re-open after policy recreate / ufw enable.
	for k := range keep {
		_ = s.FW.Open(k.port, k.proto)
	}
	_ = s.FW.EnsureBaseRules()

	sort.Strings(opened)
	sort.Strings(closed)
	audit := fmt.Sprintf("backend=%s kept=%d closed=%d", s.FW.Backend, len(keep), len(closed))
	if s.FW.Backend == firewall.BackendNftables {
		audit += " chain=" + s.FW.NftChain()
	}
	_ = s.Store.AddAudit("web", "admin", "ports.harden", "ok", audit)
	resp := map[string]any{
		"ok":        true,
		"backend":   s.FW.Backend,
		"fw_active": s.FW.Active(),
		"kept":      opened,
		"closed":    closed,
	}
	if s.FW.Backend == firewall.BackendNftables {
		resp["nft_chain"] = s.FW.NftChain()
	}
	writeJSON(w, resp)
}

func (s *Server) handlePortOpen(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, 405, "method")
		return
	}
	var body struct {
		Port  int    `json:"port"`
		Proto string `json:"proto"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, 400, "bad json")
		return
	}
	proto, err := fwd.NormalizeProto(body.Proto)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if err := s.FW.Open(body.Port, proto); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	_ = s.Store.AddAudit("web", "admin", "ports.open", "ok", fmt.Sprintf("%d/%s", body.Port, proto))
	writeJSON(w, map[string]any{"ok": true})
}

func (s *Server) handlePortClose(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, 405, "method")
		return
	}
	var body struct {
		Port     int    `json:"port"`
		Proto    string `json:"proto"`
		Confirm  bool   `json:"confirm"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, 400, "bad json")
		return
	}
	cfg := s.Cfg.Get()
	if (body.Port == cfg.ListenPort || body.Port == s.SSHPort) && !body.Confirm {
		writeErr(w, 409, "需要二次确认关闭受保护端口")
		return
	}
	proto := body.Proto
	if p, err := fwd.NormalizeProto(body.Proto); err == nil {
		proto = p
	}
	if err := s.FW.Close(body.Port, proto); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	_ = s.Store.AddAudit("web", "admin", "ports.close", "ok", fmt.Sprintf("%d/%s", body.Port, proto))
	writeJSON(w, map[string]any{"ok": true})
}

func (s *Server) handleTG(w http.ResponseWriter, r *http.Request) {
	cfg := s.Cfg.Get()
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, map[string]any{
			"enabled":   cfg.TGEnabled,
			"token_set": cfg.TGToken != "",
			"admin_ids": cfg.TGAdminIDs,
		})
	case http.MethodPost:
		var body struct {
			Enabled  bool    `json:"enabled"`
			Token    string  `json:"token"`
			AdminIDs []int64 `json:"admin_ids"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeErr(w, 400, "bad json")
			return
		}
		_ = s.Cfg.Update(func(c *config.Config) {
			c.TGEnabled = body.Enabled
			if body.Token != "" {
				c.TGToken = body.Token
			}
			c.TGAdminIDs = body.AdminIDs
		})
		writeJSON(w, map[string]any{"ok": true})
	default:
		writeErr(w, 405, "method")
	}
}

func (s *Server) handleLogs(w http.ResponseWriter, r *http.Request) {
	logs, err := s.Store.ListAudit(200)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, logs)
}

func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	cfg := s.Cfg.Get()
	switch r.Method {
	case http.MethodGet:
		tlsInfo, _ := tlsutil.Info(cfg.TLSCertFile)
		username, _, _ := s.Store.GetUser()
		latest, latestErr := fetchLatestReleaseTag()
		upd := readUpdateStatus(cfg.DataDir)
		writeJSON(w, map[string]any{
			"listen_addr":     cfg.ListenAddr,
			"listen_port":     cfg.ListenPort,
			"base_path":       cfg.BasePath,
			"iface":           cfg.Iface,
			"public_host":     cfg.PublicHost,
			"tls_mode":        cfg.TLSMode,
			"acme_email":      cfg.ACMEEmail,
			"update_url":      cfg.UpdateURL,
			"auto_update":     cfg.AutoUpdate,
			"panel_version":   cfg.PanelVersion,
			"engine_version":     cfg.EngineVer,
			"installed_version": readInstalledVersion(),
			"latest_version":  latest,
			"update_available": latest != "" && normalizeVer(latest) != normalizeVer(cfg.PanelVersion),
			"latest_error":    latestErr,
			"update_status":   upd,
			"tls":             tlsInfo,
			"tls_cert_file":   cfg.TLSCertFile,
			"username":        username,
			"fwd":             s.Fwd.Status(),
		})
	case http.MethodPost:
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeErr(w, 400, "bad json")
			return
		}
		_ = s.Cfg.Update(func(c *config.Config) {
			if v, ok := body["listen_port"].(float64); ok {
				c.ListenPort = int(v)
			}
			if v, ok := body["base_path"].(string); ok {
				c.BasePath = normalizeBasePath(v)
			}
			if v, ok := body["listen_addr"].(string); ok {
				c.ListenAddr = v
			}
			if v, ok := body["iface"].(string); ok {
				c.Iface = v
			}
			if v, ok := body["update_url"].(string); ok {
				c.UpdateURL = v
			}
			if v, ok := body["auto_update"].(bool); ok {
				c.AutoUpdate = v
			}
			if v, ok := body["public_host"].(string); ok {
				c.PublicHost = v
			}
			if v, ok := body["acme_email"].(string); ok {
				c.ACMEEmail = v
			}
		})
		cfg = s.Cfg.Get()
		if err := s.Fwd.ApplyRuntimeConfig(cfg.Iface); err != nil {
			writeErr(w, 500, "应用运行时配置失败: "+err.Error())
			return
		}
		writeJSON(w, map[string]any{"ok": true, "note": "监听地址/端口/网卡变更需重启服务生效"})
	default:
		writeErr(w, 405, "method")
	}
}

func (s *Server) handleAccount(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, 405, "method")
		return
	}
	var body struct {
		Username    string `json:"username"`
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, 400, "bad json")
		return
	}
	body.Username = strings.TrimSpace(body.Username)
	changed := []string{}
	if body.Username != "" {
		cur, _, err := s.Store.GetUser()
		if err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		if body.Username != cur {
			if err := s.Auth.SetUsername(body.Username); err != nil {
				writeErr(w, 400, err.Error())
				return
			}
			changed = append(changed, "username")
			_ = s.Store.AddAudit("web", cur, "auth.username", "ok", body.Username)
		}
	}
	if body.NewPassword != "" {
		if body.OldPassword == "" {
			writeErr(w, 400, "修改密码需要填写当前密码")
			return
		}
		if len(body.NewPassword) < 8 {
			writeErr(w, 400, "新密码至少 8 位")
			return
		}
		if err := s.Auth.ChangePassword(body.OldPassword, body.NewPassword); err != nil {
			writeErr(w, 400, err.Error())
			return
		}
		changed = append(changed, "password")
		_ = s.Store.AddAudit("web", "admin", "auth.password", "ok", "")
	}
	if len(changed) == 0 {
		writeErr(w, 400, "未检测到变更：请填写新用户名，或同时填写当前密码与新密码")
		return
	}
	writeJSON(w, map[string]any{"ok": true, "changed": changed})
}

func (s *Server) handleRestart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, 405, "method")
		return
	}
	_ = s.Store.AddAudit("web", "admin", "panel.restart", "ok", "")
	writeJSON(w, map[string]any{"ok": true, "note": "面板将在约 1 秒后重启"})
	go func() {
		time.Sleep(800 * time.Millisecond)
		_ = exec.Command("systemctl", "restart", "realmfp.service").Run()
	}()
}

func (s *Server) handleTLSRegen(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, 405, "method")
		return
	}
	cfg := s.Cfg.Get()
	if strings.EqualFold(cfg.TLSMode, "letsencrypt") || strings.EqualFold(cfg.TLSMode, "le") ||
		strings.EqualFold(cfg.TLSMode, "zerossl") || strings.EqualFold(cfg.TLSMode, "zero") {
		writeErr(w, 400, "当前为公共 CA 证书，请用「安装证书」或服务器执行: realmfp cert")
		return
	}
	// only regenerate local self-signed files under data dir
	cert := cfg.TLSCertFile
	key := cfg.TLSKeyFile
	_ = os.Remove(cert)
	_ = os.Remove(key)
	hosts := []string{"127.0.0.1"}
	if cfg.PublicHost != "" {
		hosts = append(hosts, cfg.PublicHost)
	}
	if err := tlsutil.Generate(cert, key, hosts); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, map[string]any{"ok": true, "note": "自签证书已重生，重启服务后生效"})
}

func (s *Server) handleTLSIssue(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, 405, "method")
		return
	}
	var body struct {
		Mode   string `json:"mode"` // selfsigned | letsencrypt | zerossl
		Domain string `json:"domain"`
		Email  string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, 400, "bad json")
		return
	}
	mode := strings.ToLower(strings.TrimSpace(body.Mode))
	if mode == "" {
		mode = "selfsigned"
	}
	domain := strings.TrimSpace(body.Domain)
	if domain == "" {
		domain = s.Cfg.Get().PublicHost
	}
	if (mode == "zerossl" || mode == "zero") && strings.TrimSpace(body.Email) == "" {
		writeErr(w, 400, "ZeroSSL 需要填写邮箱")
		return
	}
	script := "/usr/local/sbin/realmfp-issue-cert"
	if _, err := os.Stat(script); err != nil {
		writeErr(w, 500, "证书脚本不存在，请在服务器运行: realmfp cert")
		return
	}
	args := []string{mode, domain, body.Email}
	_ = s.Store.AddAudit("web", "admin", "tls.issue", "ok", mode+" "+domain)
	writeJSON(w, map[string]any{"ok": true, "note": "正在申请证书，约 10–60 秒后自动重启"})
	go func() {
		cmd := exec.Command(script, args...)
		_ = cmd.Run()
		time.Sleep(500 * time.Millisecond)
		_ = exec.Command("systemctl", "restart", "realmfp.service").Run()
	}()
}

func (s *Server) handleUpdateStatus(w http.ResponseWriter, r *http.Request) {
	cfg := s.Cfg.Get()
	st := readUpdateStatus(cfg.DataDir)
	latest, _ := fetchLatestReleaseTag()
	writeJSON(w, map[string]any{
		"status":            st,
		"panel_version":     cfg.PanelVersion,
		"installed_version": readInstalledVersion(),
		"latest_version":    latest,
		"log_tail":          readUpdateLogTail(cfg.DataDir, 40),
	})
}

func (s *Server) handleUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, 405, "method")
		return
	}
	var body struct {
		Tag string `json:"tag"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)

	cfg := s.Cfg.Get()
	st := readUpdateStatus(cfg.DataDir)
	if s, _ := st["state"].(string); s == "running" {
		writeErr(w, 409, "更新正在进行中，请稍候刷新查看状态")
		return
	}

	helper := "/usr/local/sbin/realmfp-do-update"
	if _, err := os.Stat(helper); err != nil {
		// fallback: still avoid cgroup kill via systemd-run + realmfp
		helper = "/usr/local/bin/realmfp"
	}

	_ = s.Store.AddAudit("web", "admin", "panel.update", "ok", body.Tag)
	// Start outside the panel cgroup — otherwise systemctl restart kills the updater.
	_ = exec.Command("systemctl", "reset-failed", "realmfp-manual-update.service").Run()
	args := []string{"--unit=realmfp-manual-update", "--collect", "--no-block", helper}
	if helper == "/usr/local/sbin/realmfp-do-update" {
		if body.Tag != "" {
			args = append(args, body.Tag)
		}
	} else {
		args = append(args, "update")
		if body.Tag != "" {
			args = append(args, body.Tag)
		}
	}
	cmd := exec.Command("systemd-run", args...)
	cmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
	out, err := cmd.CombinedOutput()
	if err != nil {
		// last-resort: nohup detached (also outside panel restart cgroup kill if already forked)
		script := helper
		if helper == "/usr/local/bin/realmfp" {
			script = helper + " update " + shellQuote(body.Tag)
		} else if body.Tag != "" {
			script = helper + " " + shellQuote(body.Tag)
		}
		nohup := exec.Command("bash", "-c", "nohup "+script+" >>/var/lib/realmfp/update.log 2>&1 &")
		_ = nohup.Start()
		writeJSON(w, map[string]any{
			"ok":      true,
			"note":    "已后台启动更新（nohup 回退）",
			"detail":  strings.TrimSpace(string(out)) + "; " + err.Error(),
			"started": true,
		})
		return
	}
	writeJSON(w, map[string]any{
		"ok":      true,
		"note":    "已启动独立更新任务，完成后服务会自动重启；请关注下方状态",
		"detail":  strings.TrimSpace(string(out)),
		"started": true,
	})
}

func shellQuote(s string) string {
	if s == "" {
		return ""
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func normalizeVer(v string) string {
	v = strings.TrimSpace(v)
	return strings.TrimPrefix(v, "v")
}

func readInstalledVersion() string {
	b, err := os.ReadFile("/opt/realmfp/VERSION")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func fetchLatestReleaseTag() (string, string) {
	client := &http.Client{Timeout: 8 * time.Second}
	req, err := http.NewRequest(http.MethodGet, "https://api.github.com/repos/gzjacktang/realmforward/releases/latest", nil)
	if err != nil {
		return "", err.Error()
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "realm-forward-panel")
	res, err := client.Do(req)
	if err != nil {
		return "", err.Error()
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if res.StatusCode >= 300 {
		return "", fmt.Sprintf("github HTTP %d", res.StatusCode)
	}
	var obj struct {
		TagName string `json:"tag_name"`
	}
	if err := json.Unmarshal(body, &obj); err != nil {
		return "", err.Error()
	}
	return obj.TagName, ""
}

func readUpdateStatus(dataDir string) map[string]any {
	path := filepath.Join(dataDir, "update-status.json")
	b, err := os.ReadFile(path)
	if err != nil {
		return map[string]any{"state": "idle"}
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return map[string]any{"state": "idle"}
	}
	return m
}

func readUpdateLogTail(dataDir string, n int) string {
	path := filepath.Join(dataDir, "update.log")
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	lines := strings.Split(string(b), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

func (s *Server) handleUninstall(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, 405, "method")
		return
	}
	var body struct {
		Confirm  string `json:"confirm"`
		WipeData bool   `json:"wipe_data"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	if body.Confirm != "UNINSTALL" {
		writeErr(w, 400, "请在 confirm 字段填入 UNINSTALL 以确认")
		return
	}
	_ = s.Store.AddAudit("web", "admin", "panel.uninstall", "ok", "")
	writeJSON(w, map[string]any{"ok": true, "note": "正在卸载，连接即将断开"})
	go func() {
		time.Sleep(800 * time.Millisecond)
		script := `set -e
systemctl stop realmfp.service 2>/dev/null || true
systemctl disable realmfp.service 2>/dev/null || true
pkill -x realm 2>/dev/null || true
nft delete table ip nftfp 2>/dev/null || true
systemctl stop realmfp-update.timer 2>/dev/null || true
systemctl disable realmfp-update.timer 2>/dev/null || true
rm -f /etc/systemd/system/realmfp.service /etc/systemd/system/realmfp-update.service /etc/systemd/system/realmfp-update.timer
systemctl daemon-reload
rm -f /usr/local/bin/realm-panel /usr/local/bin/realmfp /usr/local/bin/realm
		rm -f /usr/local/sbin/realmfp-issue-cert /usr/local/sbin/realmfp-auto-update /usr/local/sbin/realmfp-do-update
rm -rf /usr/lib/realmfp /usr/share/realmfp /opt/realmfp
`
		// Default wipe: clearing config/db/certs so reinstall shows setup again.
		if body.WipeData {
			script += "rm -rf /var/lib/realmfp\n"
		}
		_ = exec.Command("bash", "-c", script).Run()
	}()
}

func (s *Server) syncFwd() error {
	rules, err := s.Store.ListForwards()
	if err != nil {
		return err
	}
	xr := make([]fwd.Rule, 0, len(rules))
	for _, r := range rules {
		xr = append(xr, fwd.Rule{
			ID: uint32(r.ID), LocalPort: uint16(r.LocalPort),
			DestIP: r.DestIP, DestPort: uint16(r.DestPort),
			Proto: r.Proto, Enabled: r.Enabled,
		})
	}
	st := s.Fwd.Status()
	if !st.Loaded {
		return nil
	}
	return s.Fwd.SyncRules(xr)
}

func normalizeBasePath(v string) string {
	v = strings.TrimSpace(v)
	if v == "" || v == "/" {
		return "/"
	}
	if !strings.HasPrefix(v, "/") {
		v = "/" + v
	}
	return strings.TrimSuffix(v, "/")
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": msg})
}
