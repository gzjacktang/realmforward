#!/usr/bin/env bash
# 兼容旧入口：转发到 Releases 一键安装
exec bash "$(cd "$(dirname "$0")" && pwd)/install-remote.sh" "$@"
