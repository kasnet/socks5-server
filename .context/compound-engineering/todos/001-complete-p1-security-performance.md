---
status: complete
priority: p1
issue_id: "001"
tags: [go, security, performance]
dependencies: []
---

## Problem Statement

用户要求优化项目的安全与性能；当前公开监听、无认证、无超时、无连接限制，且协议校验和测试存在缺陷。

## Findings

main.go 使用无边界 Split 解析凭证。DNS/拨号忽略 context。Serve 为每个连接无限创建协程。go vet 报告测试子协程 Fatalf 及不可达代码。

## Proposed Solutions

1. 在现有接口上加入校验、资源边界、安全默认值与针对性测试。
2. 替换整个 SOCKS5 实现，迁移成本高且没有必要。

## Recommended Action

按 docs/plans/2026-10-06-security-performance.md 顺序在当前项目内完成加固。

## Acceptance Criteria

- [x] 非法协议与配置稳定返回错误。
- [x] 超时、并发限制、目标规则和关闭路径有回归测试。
- [x] 实际 CONNECT 与半关闭行为通过测试。
- [x] 完整测试、race、vet 与构建通过。
- [x] 文档记录默认值、兼容性变化及部署方法。

## Work Log

2026-10-06：完成代码初查；现有 go test 通过，go vet 报告 11 项问题，开始执行。

2026-10-06：完成安全默认值、协议校验、连接上限、超时、SSRF 目标拦截、优雅关闭和生命周期回归测试；go test、go test -race、go vet、go build 全部通过。
