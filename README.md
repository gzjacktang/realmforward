# XDP Forward Panel

Debian / Ubuntu 上的 **eBPF/XDP 四层转发面板**：Web 管理 + 防火墙端口 + Telegram 机器人。

仓库：<https://github.com/gzjacktang/xdpforward>

## 一键安装（VPS）

以 **root** 在 Debian 11+ / Ubuntu 20.04+ 执行：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/gzjacktang/xdpforward/main/utils/install-remote.sh)
```

安装完成后，日常管理命令为 **`xdp`**：

```bash
xdp              # 交互菜单：状态 / 启停 / 更新 / 改密 / 证书 / 卸载
xdp status
xdp update
xdp passwd
xdp cert
xdp uninstall
```

面板默认：`https://<IP或域名>:2888`  
首次账号密码见安装日志：`journalctl -u xdp-forward-panel -n 80 --no-pager`

## 功能摘要

| 能力 | 说明 |
|---|---|
| XDP 转发 | DNAT + SNAT，协议 tcp / udp / both |
| SNAT 段 | 默认 `40000-49999`（写入 `ip_local_reserved_ports`，不开放防火墙） |
| 防火墙 | ufw / nft / iptables 检测与放行 |
| Web 设置 | 更新、卸载、改用户名密码、安装证书、重启 |
| TLS | 自签 或 Let's Encrypt（`xdp cert` / 面板「安装证书」） |

## 目录

```
project/frontend/    Web 静态前端
project/backend/     Go 面板 + XDP BPF
utils/               安装 / xdp CLI / systemd
doc/                 计划与架构
```

## 系统要求

- Debian 11+ / Ubuntu 20.04+
- 内核 ≥ 5.10
- XDP：native 优先，否则 generic；都失败则服务启动失败（不降级静默）

## 从源码安装

```bash
git clone https://github.com/gzjacktang/xdpforward.git /opt/xdp-forward-panel
bash /opt/xdp-forward-panel/utils/install.sh
# 或
xdp install
```

## 安全提示

- 勿把 SSH 密码、Bot Token、面板密码写入仓库
- 生产环境建议域名 + Let's Encrypt，并限制面板端口来源
