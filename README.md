# NFT Forward Panel

基于 **nftables** 的 IPv4 端口转发面板（DNAT + masquerade）。

> 原 XDP 版本（`xdpforward`）已废弃，请使用本仓库。

## 一键安装

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/gzjacktang/nftforward/main/utils/install-remote.sh)
```

管理命令：`nftfp`（status / update / cert / passwd / uninstall）

## 特性

- nftables DNAT + masquerade，内核/网卡校验和卸载
- Web 面板：转发规则、防火墙端口、证书、更新
- 支持 tcp / udp / both
- systemd 服务与自动更新

## 默认

- 面板端口：`2888`（HTTPS）
- 数据目录：`/var/lib/nftfp`
- 服务名：`nftfp.service`
