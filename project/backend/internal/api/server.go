package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/wuling/xdp-forward-panel/internal/auth"
	"github.com/wuling/xdp-forward-panel/internal/config"
	"github.com/wuling/xdp-forward-panel/internal/firewall"
	"github.com/wuling/xdp-forward-panel/internal/listen"
	"github.com/wuling/xdp-forward-panel/internal/store"
	"github.com/wuling/xdp-forward-panel/internal/tlsutil"
	"github.com/wuling/xdp-forward-panel/internal/xdp"
)

type Server struct {
	Cfg      *config.Manager
	Store    *store.Store
	Auth     *auth.Service
	XDP      *xdp.Manager
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
	mux.HandleFunc(api("/tg"), s.requireAuth(s.handleTG))
	mux.HandleFunc(api("/logs"), s.requireAuth(s.handleLogs))
	mux.HandleFunc(api("/settings"), s.requireAuth(s.handleSettings))
	mux.HandleFunc(api("/settings/account"), s.requireAuth(s.handleAccount))
	mux.HandleFunc(api("/settings/tls/regen"), s.requireAuth(s.handleTLSRegen))
	mux.HandleFunc(api("/settings/tls/issue"), s.requireAuth(s.handleTLSIssue))
	mux.HandleFunc(api("/settings/restart"), s.requireAuth(s.handleRestart))
	mux.HandleFunc(api("/settings/update"), s.requireAuth(s.handleUpdate))
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
	xs := s.XDP.Status()
	writeJSON(w, map[string]any{
		"panel_version": cfg.PanelVersion,
		"bpf_version":   cfg.BPFVersion,
		"xdp":           xs,
		"firewall":      s.FW.Backend,
		"listen":        fmt.Sprintf("%s:%d", cfg.ListenAddr, cfg.ListenPort),
		"base_path":     cfg.BasePath,
		"snat":          fmt.Sprintf("%d-%d", cfg.SNATPortMin, cfg.SNATPortMax),
		"tg_enabled":    cfg.TGEnabled,
		"warning":       "XDP 在 netfilter 之前执行，转发端口会绕过防火墙。",
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
		st := s.XDP.GetStats()
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
		proto, err := xdp.NormalizeProto(body.Proto)
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
		if err := s.syncXDP(); err != nil {
			writeErr(w, 500, "saved but xdp sync: "+err.Error())
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
		_ = s.syncXDP()
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
		proto, err := xdp.NormalizeProto(body.Proto)
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
		_ = s.syncXDP()
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
		_ = s.syncXDP()
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
		XDP       string `json:"xdp"`
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
		xdpTag := "—"
		for _, fr := range rules {
			if !fr.Enabled || fr.LocalPort != port {
				continue
			}
			fp := strings.ToLower(fr.Proto)
			if fp == proto || fp == "both" || fp == "tcp+udp" {
				xdpTag = fmt.Sprintf("fwd #%d", fr.ID)
				break
			}
		}
		prot := port == cfg.ListenPort || (s.SSHPort > 0 && port == s.SSHPort)
		seen[k] = row{Port: port, Proto: proto, Firewall: fw, Listening: lis, XDP: xdpTag, Protected: prot}
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
		hasBiz := v.Listening != "无" || v.XDP != "—" || v.Protected
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
			if merged.XDP == "—" && udp.XDP != "—" {
				merged.XDP = udp.XDP
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
	writeJSON(w, map[string]any{"backend": s.FW.Backend, "ports": out, "ssh_port": s.SSHPort, "page_size": 20})
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
	proto, err := xdp.NormalizeProto(body.Proto)
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
	if p, err := xdp.NormalizeProto(body.Proto); err == nil {
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
		writeJSON(w, map[string]any{
			"listen_addr":   cfg.ListenAddr,
			"listen_port":   cfg.ListenPort,
			"base_path":     cfg.BasePath,
			"iface":         cfg.Iface,
			"public_host":   cfg.PublicHost,
			"tls_mode":      cfg.TLSMode,
			"acme_email":    cfg.ACMEEmail,
			"snat_min":      cfg.SNATPortMin,
			"snat_max":      cfg.SNATPortMax,
			"update_url":    cfg.UpdateURL,
			"auto_update":   cfg.AutoUpdate,
			"panel_version": cfg.PanelVersion,
			"bpf_version":   cfg.BPFVersion,
			"tls":           tlsInfo,
			"tls_cert_file": cfg.TLSCertFile,
			"username":      username,
			"xdp":           s.XDP.Status(),
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
			if v, ok := body["snat_min"].(float64); ok {
				c.SNATPortMin = uint16(v)
			}
			if v, ok := body["snat_max"].(float64); ok {
				c.SNATPortMax = uint16(v)
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
		_ = s.XDP.ApplyReservedPorts(cfg.SNATPortMin, cfg.SNATPortMax)
		writeJSON(w, map[string]any{"ok": true, "note": "监听地址/端口变更需重启服务生效"})
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
		_ = exec.Command("systemctl", "restart", "xdp-forward-panel.service").Run()
	}()
}

func (s *Server) handleTLSRegen(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, 405, "method")
		return
	}
	cfg := s.Cfg.Get()
	if strings.EqualFold(cfg.TLSMode, "letsencrypt") || strings.EqualFold(cfg.TLSMode, "le") {
		writeErr(w, 400, "当前为 Let's Encrypt，请用「安装证书」或服务器执行: xdp cert")
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
		Mode   string `json:"mode"` // selfsigned | letsencrypt
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
	script := "/usr/local/sbin/xdp-panel-issue-cert"
	if _, err := os.Stat(script); err != nil {
		writeErr(w, 500, "证书脚本不存在，请在服务器运行: xdp cert")
		return
	}
	args := []string{mode, domain, body.Email}
	_ = s.Store.AddAudit("web", "admin", "tls.issue", "ok", mode+" "+domain)
	writeJSON(w, map[string]any{"ok": true, "note": "正在申请证书，约 10–60 秒后自动重启"})
	go func() {
		cmd := exec.Command(script, args...)
		_ = cmd.Run()
		time.Sleep(500 * time.Millisecond)
		_ = exec.Command("systemctl", "restart", "xdp-forward-panel.service").Run()
	}()
}

func (s *Server) handleUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, 405, "method")
		return
	}
	_ = s.Store.AddAudit("web", "admin", "panel.update", "ok", "")
	writeJSON(w, map[string]any{"ok": true, "note": "已开始后台更新，完成后服务会重启"})
	go func() {
		time.Sleep(500 * time.Millisecond)
		cmd := exec.Command("/usr/local/bin/xdp", "update")
		cmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
		_ = cmd.Run()
	}()
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
systemctl stop xdp-forward-panel.service 2>/dev/null || true
systemctl disable xdp-forward-panel.service 2>/dev/null || true
systemctl stop xdp-panel-update.timer 2>/dev/null || true
systemctl disable xdp-panel-update.timer 2>/dev/null || true
rm -f /etc/systemd/system/xdp-forward-panel.service /etc/systemd/system/xdp-panel-update.service /etc/systemd/system/xdp-panel-update.timer
systemctl daemon-reload
rm -f /usr/local/bin/xdp-panel /usr/local/bin/xdp
rm -f /usr/local/sbin/xdp-panel-issue-cert /usr/local/sbin/xdp-panel-auto-update
rm -rf /usr/lib/xdp-forward-panel /usr/share/xdp-forward-panel
`
		if body.WipeData {
			script += "rm -rf /var/lib/xdp-forward-panel\n"
		}
		_ = exec.Command("bash", "-c", script).Run()
	}()
}

func (s *Server) syncXDP() error {
	rules, err := s.Store.ListForwards()
	if err != nil {
		return err
	}
	xr := make([]xdp.Rule, 0, len(rules))
	for _, r := range rules {
		xr = append(xr, xdp.Rule{
			ID: uint32(r.ID), LocalPort: uint16(r.LocalPort),
			DestIP: r.DestIP, DestPort: uint16(r.DestPort),
			Proto: r.Proto, Enabled: r.Enabled,
		})
	}
	st := s.XDP.Status()
	if !st.Loaded {
		return nil
	}
	return s.XDP.SyncRules(xr)
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
