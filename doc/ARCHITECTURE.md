# 架构说明（草案）

## 总览

```
浏览器 / Telegram
        │
        ▼
┌───────────────────────────────┐
│  Go Panel (:2888)             │
│  HTTP API + 静态前端 + TG Bot │
│  auth · audit · store(SQLite) │
└───────────┬───────────────────┘
            │
   ┌────────┼────────┐
   ▼        ▼        ▼
 XDP/eBPF  Firewall  ss 探测
 (maps)   ufw|nft|ipt
```

## XDP 包路径（IPv4）

```
Client ──► NIC ──► XDP
                    │ hit rule?
                    ├─ no  → XDP_PASS
                    └─ yes → DNAT+SNAT
                              → fib_lookup
                              → XDP_TX / REDIRECT ──► Backend
Backend ──► NIC ──► XDP
                    │ ct lookup?
                    ├─ hit → rewrite → Client
                    └─ miss → XDP_PASS
```

## 防火墙适配优先级

`ufw`（若 active）→ `nftables` → `iptables-nft` / `iptables-legacy`

## 安全要点

- 会话 Cookie：HttpOnly、SameSite=Lax；生产建议配合反代 HTTPS
- TG：仅白名单 user id；危险操作 inline keyboard 确认
- 关闭 SSH / 面板端口：二次确认
- 密钥与密码：仅存本机配置/SQLite，不进 git
- XDP 绕过 netfilter：UI 与日志永久提示
