package tgbot

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/wuling/xdp-forward-panel/internal/config"
	"github.com/wuling/xdp-forward-panel/internal/firewall"
	"github.com/wuling/xdp-forward-panel/internal/store"
	"github.com/wuling/xdp-forward-panel/internal/xdp"
)

type Bot struct {
	cfg   *config.Manager
	store *store.Store
	fw    *firewall.Manager
	xdp   *xdp.Manager
	syncX func() error

	mu     sync.Mutex
	stopCh chan struct{}
	offset int64
}

func New(cfg *config.Manager, st *store.Store, fw *firewall.Manager, xm *xdp.Manager, syncX func() error) *Bot {
	return &Bot{cfg: cfg, store: st, fw: fw, xdp: xm, syncX: syncX, stopCh: make(chan struct{})}
}

func (b *Bot) Start() {
	go b.loop()
}

func (b *Bot) Stop() {
	select {
	case <-b.stopCh:
	default:
		close(b.stopCh)
	}
}

func (b *Bot) loop() {
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-b.stopCh:
			return
		case <-t.C:
			c := b.cfg.Get()
			if !c.TGEnabled || c.TGToken == "" {
				continue
			}
			b.poll(c)
		}
	}
}

func (b *Bot) poll(c config.Config) {
	u := fmt.Sprintf("https://api.telegram.org/bot%s/getUpdates?timeout=0&offset=%d", c.TGToken, b.offset)
	resp, err := http.Get(u)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	var payload struct {
		OK     bool `json:"ok"`
		Result []struct {
			UpdateID int64 `json:"update_id"`
			Message  *struct {
				Text string `json:"text"`
				From *struct {
					ID int64 `json:"id"`
				} `json:"from"`
				Chat struct {
					ID int64 `json:"id"`
				} `json:"chat"`
			} `json:"message"`
			CallbackQuery *struct {
				ID   string `json:"id"`
				Data string `json:"data"`
				From struct {
					ID int64 `json:"id"`
				} `json:"from"`
				Message struct {
					Chat struct {
						ID int64 `json:"id"`
					} `json:"chat"`
				} `json:"message"`
			} `json:"callback_query"`
		} `json:"result"`
	}
	body, _ := io.ReadAll(resp.Body)
	if json.Unmarshal(body, &payload) != nil || !payload.OK {
		return
	}
	for _, up := range payload.Result {
		if up.UpdateID >= b.offset {
			b.offset = up.UpdateID + 1
		}
		if up.CallbackQuery != nil {
			if !b.isAdmin(c, up.CallbackQuery.From.ID) {
				continue
			}
			b.handleCallback(c, up.CallbackQuery.Message.Chat.ID, up.CallbackQuery.Data)
			continue
		}
		if up.Message == nil || up.Message.From == nil {
			continue
		}
		if !b.isAdmin(c, up.Message.From.ID) {
			continue
		}
		b.handleCommand(c, up.Message.Chat.ID, up.Message.From.ID, strings.TrimSpace(up.Message.Text))
	}
}

func (b *Bot) isAdmin(c config.Config, id int64) bool {
	for _, a := range c.TGAdminIDs {
		if a == id {
			return true
		}
	}
	return false
}

func (b *Bot) handleCommand(c config.Config, chatID, userID int64, text string) {
	fields := strings.Fields(text)
	if len(fields) == 0 {
		return
	}
	cmd := fields[0]
	actor := fmt.Sprintf("uid:%d", userID)
	switch {
	case cmd == "/status":
		xs := b.xdp.Status()
		b.send(c, chatID, fmt.Sprintf("XDP loaded=%v mode=%s iface=%s\nFW=%s\nSNAT=%d-%d",
			xs.Loaded, xs.Mode, xs.Iface, b.fw.Backend, c.SNATPortMin, c.SNATPortMax))
	case cmd == "/ports":
		b.send(c, chatID, fmt.Sprintf("防火墙后端: %s\n用面板查看三层状态，或 /open /close", b.fw.Backend))
	case cmd == "/stats":
		st := b.xdp.GetStats()
		var sb strings.Builder
		sb.WriteString("规则统计:\n")
		for id, s := range st {
			sb.WriteString(fmt.Sprintf("#%d pkts=%d bytes=%d\n", id, s.Packets, s.Bytes))
		}
		b.send(c, chatID, sb.String())
	case cmd == "/fwd" && len(fields) >= 2 && fields[1] == "list":
		rules, _ := b.store.ListForwards()
		var sb strings.Builder
		for _, r := range rules {
			en := "off"
			if r.Enabled {
				en = "on"
			}
			sb.WriteString(fmt.Sprintf("#%d %d -> %s:%d %s [%s]\n", r.ID, r.LocalPort, r.DestIP, r.DestPort, r.Proto, en))
		}
		if sb.Len() == 0 {
			sb.WriteString("(empty)")
		}
		b.send(c, chatID, sb.String())
	case cmd == "/fwd" && len(fields) >= 3 && fields[1] == "del":
		id := fields[2]
		b.sendConfirm(c, chatID, "确认删除转发 "+id+"？", "fwd_del:"+id)
	case cmd == "/fwd" && len(fields) >= 6 && fields[1] == "add":
		lport, _ := strconv.Atoi(fields[2])
		dip := fields[3]
		dport, _ := strconv.Atoi(fields[4])
		proto := fields[5]
		id, err := b.store.AddForward(lport, dip, dport, proto, "", true)
		if err != nil {
			b.send(c, chatID, "fail: "+err.Error())
			return
		}
		_ = b.syncX()
		_ = b.store.AddAudit("tg", actor, "fwd.add", "ok", fmt.Sprintf("%d", id))
		b.send(c, chatID, fmt.Sprintf("added #%d", id))
	case cmd == "/open" && len(fields) >= 3:
		port, _ := strconv.Atoi(fields[1])
		proto := fields[2]
		if err := b.fw.Open(port, proto); err != nil {
			b.send(c, chatID, err.Error())
			return
		}
		_ = b.store.AddAudit("tg", actor, "ports.open", "ok", fmt.Sprintf("%d/%s", port, proto))
		b.send(c, chatID, "opened")
	case cmd == "/close" && len(fields) >= 3:
		port := fields[1]
		proto := fields[2]
		b.sendConfirm(c, chatID, fmt.Sprintf("确认关闭端口 %s/%s？", port, proto), "port_close:"+port+":"+proto)
	default:
		b.send(c, chatID, "命令: /status /ports /open /close /fwd add|del|list /stats")
	}
}

func (b *Bot) handleCallback(c config.Config, chatID int64, data string) {
	switch {
	case strings.HasPrefix(data, "fwd_del:"):
		id, _ := strconv.ParseInt(strings.TrimPrefix(data, "fwd_del:"), 10, 64)
		_ = b.store.DeleteForward(id)
		_ = b.syncX()
		_ = b.store.AddAudit("tg", "callback", "fwd.del", "ok", fmt.Sprintf("%d", id))
		b.send(c, chatID, "deleted")
	case strings.HasPrefix(data, "port_close:"):
		parts := strings.Split(strings.TrimPrefix(data, "port_close:"), ":")
		if len(parts) != 2 {
			return
		}
		port, _ := strconv.Atoi(parts[0])
		proto := parts[1]
		_ = b.fw.Close(port, proto)
		_ = b.store.AddAudit("tg", "callback", "ports.close", "ok", fmt.Sprintf("%d/%s", port, proto))
		b.send(c, chatID, "closed")
	}
}

func (b *Bot) send(c config.Config, chatID int64, text string) {
	api := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", c.TGToken)
	form := url.Values{}
	form.Set("chat_id", strconv.FormatInt(chatID, 10))
	form.Set("text", text)
	_, _ = http.PostForm(api, form)
}

func (b *Bot) sendConfirm(c config.Config, chatID int64, text, callback string) {
	api := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", c.TGToken)
	kb, _ := json.Marshal(map[string]any{
		"inline_keyboard": [][]map[string]string{{{
			"text": "确认", "callback_data": callback,
		}, {
			"text": "取消", "callback_data": "noop",
		}}},
	})
	form := url.Values{}
	form.Set("chat_id", strconv.FormatInt(chatID, 10))
	form.Set("text", text)
	form.Set("reply_markup", string(kb))
	_, _ = http.PostForm(api, form)
}
