package main

import (
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/wuling/xdp-forward-panel/internal/api"
	"github.com/wuling/xdp-forward-panel/internal/auth"
	"github.com/wuling/xdp-forward-panel/internal/config"
	"github.com/wuling/xdp-forward-panel/internal/firewall"
	"github.com/wuling/xdp-forward-panel/internal/store"
	"github.com/wuling/xdp-forward-panel/internal/tgbot"
	"github.com/wuling/xdp-forward-panel/internal/tlsutil"
	"github.com/wuling/xdp-forward-panel/internal/version"
	"github.com/wuling/xdp-forward-panel/internal/xdp"
)

func main() {
	showVersion := flag.Bool("version", false, "print version and exit")
	dataDir := flag.String("data", "/var/lib/xdp-forward-panel", "data directory")
	iface := flag.String("iface", "", "network interface for XDP (default: auto)")
	bpfObj := flag.String("bpf", "", "path to xdp_forward.o")
	webDir := flag.String("web", "", "static web directory")
	noXDP := flag.Bool("no-xdp", false, "skip XDP load (API-only mode)")
	flag.Parse()
	if *showVersion {
		fmt.Println(version.Version)
		return
	}

	if err := os.MkdirAll(*dataDir, 0o755); err != nil {
		log.Fatal(err)
	}
	cfgPath := filepath.Join(*dataDir, "config.json")
	cfgMgr, err := config.LoadOrCreate(cfgPath, *dataDir)
	if err != nil {
		log.Fatal(err)
	}
	cfg := cfgMgr.Get()

	st, err := store.Open(*dataDir)
	if err != nil {
		log.Fatal(err)
	}
	defer st.Close()

	authSvc := auth.New(st)
	created, plain, err := authSvc.EnsureFreshInstall("admin")
	if err != nil {
		log.Fatal(err)
	}
	if created {
		fmt.Println("========================================")
		fmt.Println("XDP Forward Panel — 初始账号")
		fmt.Println("用户名: admin")
		fmt.Printf("密码:   %s\n", plain)
		fmt.Println("请立即登录后修改密码；此密码只显示一次。")
		fmt.Println("========================================")
	}

	xm := xdp.New()
	xm.SetObjectPath(*bpfObj)

	fw := firewall.Detect()
	log.Printf("firewall backend: %s", fw.Backend)

	useIface := *iface
	if useIface == "" {
		useIface = cfg.Iface
	}
	if useIface == "" {
		useIface = detectDefaultIface()
	}

	if !*noXDP {
		csumMode := uint8(0)
		if cfg.CsumFast {
			csumMode = 1
		}
		if err := xm.Load(useIface, cfg.XDPMode, cfg.SNATPortMin, cfg.SNATPortMax, csumMode); err != nil {
			log.Printf("XDP load failed: %v", err)
			log.Fatal("按设计：XDP 加载失败不降级，进程退出。可用 -no-xdp 仅调试 API。")
		}
		log.Printf("XDP loaded on %s mode=%s", useIface, xm.Status().Mode)
		_ = cfgMgr.Update(func(c *config.Config) { c.Iface = useIface })
		// sync DB rules
		rules, _ := st.ListForwards()
		xr := make([]xdp.Rule, 0, len(rules))
		for _, r := range rules {
			xr = append(xr, xdp.Rule{
				ID: uint32(r.ID), LocalPort: uint16(r.LocalPort),
				DestIP: r.DestIP, DestPort: uint16(r.DestPort),
				Proto: r.Proto, Enabled: r.Enabled,
			})
		}
		if err := xm.SyncRules(xr); err != nil {
			log.Printf("sync rules: %v", err)
		}
	} else {
		log.Printf("running with -no-xdp")
	}
	defer xm.Close()

	tlsHosts := []string{"127.0.0.1"}
	if cfg.PublicHost != "" {
		tlsHosts = append(tlsHosts, cfg.PublicHost)
	}
	switch strings.ToLower(cfg.TLSMode) {
	case "letsencrypt", "le", "zerossl", "zero":
		if _, err := os.Stat(cfg.TLSCertFile); err != nil {
			log.Fatalf("证书不存在: %s （请运行: xdp cert）", cfg.TLSCertFile)
		}
		if _, err := os.Stat(cfg.TLSKeyFile); err != nil {
			log.Fatalf("私钥不存在: %s", cfg.TLSKeyFile)
		}
		log.Printf("TLS mode=%s cert=%s", cfg.TLSMode, cfg.TLSCertFile)
	default:
		if err := tlsutil.Ensure(cfg.TLSCertFile, cfg.TLSKeyFile, tlsHosts); err != nil {
			log.Fatal("tls:", err)
		}
		log.Printf("TLS mode=selfsigned cert=%s", cfg.TLSCertFile)
	}

	var staticFS fs.FS
	wd := *webDir
	if wd == "" {
		wd = filepath.Join(filepath.Dir(os.Args[0]), "web")
	}
	if stInfo, err := os.Stat(wd); err == nil && stInfo.IsDir() {
		staticFS = os.DirFS(wd)
	}

	sshPort := detectSSHPort()
	srv := &api.Server{
		Cfg: cfgMgr, Store: st, Auth: authSvc, XDP: xm, FW: fw,
		Static: staticFS, SSHPort: sshPort,
	}

	bot := tgbot.New(cfgMgr, st, fw, xm, func() error {
		rules, err := st.ListForwards()
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
		if !xm.Status().Loaded {
			return nil
		}
		return xm.SyncRules(xr)
	})
	bot.Start()
	defer bot.Stop()

	addr := net.JoinHostPort(cfg.ListenAddr, strconv.Itoa(cfg.ListenPort))
	httpSrv := &http.Server{Addr: addr, Handler: srv.Handler()}

	go func() {
		log.Printf("listening https://%s (base_path=%s)", addr, cfg.BasePath)
		if err := httpSrv.ListenAndServeTLS(cfg.TLSCertFile, cfg.TLSKeyFile); err != nil && err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}()

	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	<-ch
	log.Printf("shutting down")
	_ = httpSrv.Close()
}

func detectDefaultIface() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "eth0"
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := iface.Addrs()
		if len(addrs) == 0 {
			continue
		}
		return iface.Name
	}
	return "eth0"
}

func detectSSHPort() int {
	b, err := os.ReadFile("/etc/ssh/sshd_config")
	if err != nil {
		return 22
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToLower(line), "port ") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				p, _ := strconv.Atoi(fields[1])
				if p > 0 {
					return p
				}
			}
		}
	}
	return 22
}
