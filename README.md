# Realm Forward Panel

基于 **[Realm](https://github.com/zhboner/realm)** 的 IPv4 端口转发面板（用户态 splice 零拷贝）。

> 历史：曾用 XDP / nftables NAT；同口转发易撞 softirq 上限，现改 Realm。

## 一键安装

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/gzjacktang/realmforward/main/utils/install-remote.sh)
```

管理命令：`realmfp`（status / update / cert / passwd / uninstall）

## 特性

- Realm TCP/UDP 转发（Linux splice）
- Web 面板：转发规则、防火墙端口、证书、更新
- 支持 tcp / udp / both
- systemd 服务与自动更新

## 默认

- 面板端口：`2888`（HTTPS）
- 数据目录：`/var/lib/realmfp`
- Realm 配置：`/var/lib/realmfp/realm.json`
- 服务名：`realmfp.service`
