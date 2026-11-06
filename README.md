# XDP Forward Panel

Debian / Ubuntu 上的 **eBPF/XDP 四层转发面板**：Web 管理、防火墙端口、Telegram 机器人、一键证书。

仓库：<https://github.com/gzjacktang/xdpforward>  
当前版本：**v0.2.2**

从 v0.2.0 起，安装与更新均使用 **GitHub Actions 预编译包**，VPS **无需安装 Go / clang**，`bash` 一条命令即可拉取安装。

---

## 一键安装

以 **root** 在 Debian 11+ / Ubuntu 20.04+ 执行：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/gzjacktang/xdpforward/main/utils/install-remote.sh)
```

脚本会：

1. 查询 GitHub Releases 最新版  
2. 按架构下载 `xdpforward-v*-linux-amd64|arm64.tar.gz`  
3. 安装二进制、BPF 对象、Web 前端与 `xdp` 管理命令  
4. 引导签发 TLS（自签 / Let's Encrypt / ZeroSSL）  
5. 启用 systemd 服务与每日自动更新检查  

安装完成后打开面板：

- 地址：`https://<IP或域名>:2888`  
- 首次账号密码：`journalctl -u xdp-forward-panel -n 80 --no-pager`

### 管理命令 `xdp`

```bash
xdp                 # 交互菜单
xdp status          # 状态
xdp start|stop|restart
xdp update          # 拉取最新预编译包并更新（保留配置与数据）
xdp update v0.2.0   # 指定版本
xdp passwd          # 改用户名/密码
xdp cert            # 安装/更换证书
xdp uninstall       # 卸载（可选保留数据）
```

### 系统要求

| 项目 | 要求 |
|---|---|
| 系统 | Debian 11+ / Ubuntu 20.04+ |
| 架构 | `amd64` 或 `arm64` |
| 内核 | ≥ 5.10（支持 XDP） |
| 权限 | root |
| 编译器 | **不需要**（Release 已含 `xdp-panel` + `xdp_forward.o`） |

XDP 模式：`native` 优先，失败回退 `generic`；都失败则服务启动失败（不静默降级）。

---

## 功能一览

### 转发内核（XDP）

- **DNAT + SNAT** 四层转发，协议支持 `tcp` / `udp` / `both`
- 多规则、可启用/停用，Web 与 Telegram 均可管理
- **SNAT 端口段**默认 `40000–49999`（写入 `ip_local_reserved_ports`，不额外开防火墙）
- 支持改规则、去重合并（`both` 展开为 tcp/udp 后合并）

### Web 面板（默认 2888）

- 仪表盘：规则、流量概览、XDP 挂载状态
- 转发规则 CRUD（源端口 / 目标 / 协议 / 备注）
- 防火墙：检测 ufw / **主机 nftables（优先 `inet filter` 入站链）** / iptables；开关端口与一键加固都改真正生效的规则（不再写无效的独立 `xfp` 表）
- 设置页：
  - 查看面板 / BPF 版本
  - 在线更新、卸载
  - 更改登录用户名密码
  - 安装证书、重启服务
  - 自动更新开关与更新地址

### TLS 证书

| 模式 | 说明 |
|---|---|
| 自签 | 默认，适合先跑通 |
| Let's Encrypt | `certbot` 签发 |
| ZeroSSL | `acme.sh` 签发（需邮箱） |

命令行：`xdp cert` 或面板「安装证书」。

### Telegram 机器人

- 配置 Bot Token 与管理员 ID 后启用
- 查看/增删转发规则、查询状态（与面板同一数据）

### 安装与更新机制（v0.2.0+）

| 动作 | 行为 |
|---|---|
| 安装 | `install-remote.sh` → Releases 预编译包 → `install-release.sh` |
| 手动更新 | `xdp update` 拉最新（或指定 tag）包，保留 `/var/lib/xdp-forward-panel` |
| 自动更新 | systemd timer 每日检查；面板开启「自动更新」时执行 `xdp update` |
| 源码安装 | 仍可用 `utils/install.sh`（需本机 Go + clang，开发用） |

Release 产物由 GitHub Actions 在打 `v*` tag 时构建并上传。

---

## 目录结构

```
project/frontend/     Web 静态前端
project/backend/      Go 面板 + XDP BPF
utils/                安装脚本、xdp CLI、systemd
.github/workflows/    Release 构建
VERSION               当前版本号
```

常用路径（安装后）：

| 路径 | 内容 |
|---|---|
| `/usr/local/bin/xdp-panel` | 面板服务 |
| `/usr/local/bin/xdp` | 管理 CLI |
| `/usr/lib/xdp-forward-panel/xdp_forward.o` | BPF 对象 |
| `/usr/share/xdp-forward-panel/web/` | 前端 |
| `/var/lib/xdp-forward-panel/` | 配置、SQLite、证书 |
| `/opt/xdp-forward-panel/release/` | 最近一次安装包缓存 |

---

## 从源码构建（开发者）

```bash
git clone https://github.com/gzjacktang/xdpforward.git
cd xdpforward
# 需要 Go 1.22+、clang、llvm
./utils/pack-release.sh 0.2.0 amd64
# 产物: dist/xdpforward-v0.2.0-linux-amd64.tar.gz
```

本机直接编译安装（旧路径，仍可用）：

```bash
bash utils/install.sh
```

发布新版本：改 `VERSION` → 推送 → `git tag vX.Y.Z && git push origin vX.Y.Z`，Actions 自动出包。

---

## 安全提示

- 勿把 SSH 密码、Bot Token、面板密码写入仓库或 Issue
- 生产环境建议域名 + Let's Encrypt / ZeroSSL，并限制 2888 来源
- SNAT 段占用本机临时端口，请勿与业务端口冲突
