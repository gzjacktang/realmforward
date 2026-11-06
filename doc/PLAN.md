# XDP Forward Panel — 计划草案

> 状态：**方案已确认，可进入阶段 1（Go + XDP）**  
> 技术栈：Go · eBPF/XDP · SQLite · Telegram Bot API · **纯静态前端**  
> 端口：前端开发预留 1888 · 生产 **HTTPS 自签 → 2888**  
> 项目路径：`/Users/wl/Documents/转发面板`

---

## 已确认决策

| # | 议题 | 决定 |
|---|---|---|
| 1 | UI | **蓝色系 OK**；信息架构 OK；含「面板设置」 |
| 2 | 前端 | **纯静态**（后端托管） |
| 3 | 初始账号 | 安装时 **随机密码** 并打印 |
| 4 | SNAT 保留口 | **保留机制**，默认 `40000-49999`；**不打开防火墙**，只写入 `ip_local_reserved_ports` |
| 5 | TLS / 更新 | 安装脚本 **自签证书** + **自动更新**（面板 + BPF 内核） |

---

## 1. 目标

在 Debian 11+ / Ubuntu 20.04+（内核 ≥ 5.10）上提供：

1. **XDP 四层转发**（仅 XDP；native → generic；都失败则报错）
2. **防火墙端口开关**（自动检测 ufw / nftables / iptables）
3. **Web 面板**（登录、仪表盘、规则、端口、TG、日志、**面板设置**）
4. **Telegram 机器人**（白名单管理员）

---

## 2. 面板页面

登录 · 仪表盘 · 转发规则 · 防火墙端口 · Telegram · 操作日志 · **面板设置**

### 面板设置（新增）

- **版本与更新**：面板程序更新、转发内核（XDP/BPF）更新、自动更新开关
- **访问与路径**：监听端口、Web 路径前缀（如 `/xfpanel/`）、绑定地址
- **账号**：改用户名 / 密码（bcrypt）
- **转发与 TLS**：SNAT 保留端口段、自签证书状态/重生成、更新通道 URL

---

## 3. XDP 转发（第一版）

入站 DNAT+SNAT → `bpf_fib_lookup` → `XDP_TX` / `XDP_REDIRECT`；回程 LRU CT；校验和增量更新。  
统计：每条规则包数/字节。限制：仅 IPv4、不分片、**绕过 netfilter**（UI 标明）。

### SNAT 保留端口段

XDP SNAT 会占用一段源端口。写入 `ip_local_reserved_ports`，告诉内核**不要把这段分给本机应用**，避免串包。

- 默认：`40000-49999`（已确认）
- **不会**因此在防火墙里放行这些端口；与 ufw/nft/iptables 无关
- 只影响内核本地端口分配；设置页可改范围

---

## 4. 防火墙

探测：ufw → nftables → iptables。  
三层状态：防火墙规则 · `ss` 监听 · XDP 占用。  
关闭 SSH / 面板端口：二次确认。

---

## 5. Telegram

白名单 `admin_ids`。命令：`/status` `/ports` `/open` `/close` `/fwd add|del|list` `/stats`。危险操作用按钮确认。

---

## 6. 安装 / TLS / 自动更新

- 一键安装 + systemd
- **自签证书**：安装时生成，面板 HTTPS 监听 2888；浏览器不受信属预期；设置页可重生成
- **自动更新**：定时任务检查更新通道 → 拉面板二进制 + BPF 对象 → 替换 → 重启服务（短中断可接受，更新内核前 UI 提示）
- 初始 `admin` + **随机密码** 打印到终端

---

## 7. 目录与交付

```
doc/  prototype/  project/frontend/  project/backend/  database/  utils/
```

| 阶段 | 交付物 | 状态 |
|---|---|---|
| 0 | 高保真 HTML 原型（蓝系 + 设置页） | **迭代中** |
| 1 | 后端 + XDP BPF | 待确认 |
| 2 | 纯静态前端对接 API | 待确认 |
| 3 | 安装脚本 + systemd + 自签 + 自动更新 | 待确认 |
| 4 | README | 待确认 |
| 5 | 单测 / 接口 / BPF_PROG_TEST_RUN / 浏览器 | 待确认 |

---

## 8. 下一步

方案已锁定。你回复 **开始开发** 后进入阶段 1：Go 后端 + XDP BPF。
