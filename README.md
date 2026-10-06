# SOCKS5 Server

这是一个只实现 `CONNECT` 的轻量 SOCKS5 代理，支持用户名密码认证、自定义 DNS 解析器、规则集、地址重写和自定义拨号器。

## 启动

默认只监听本机，并且拒绝无认证启动：

```bash
go run . -auth 'user:password'
```

密码可以包含冒号。需要监听局域网时显式指定地址；无认证模式必须显式开启：

```bash
go run . -addr 192.168.1.10:8182 -allow-no-auth
```

默认启用以下保护：

- SOCKS 握手和 DNS/建连超时均为 10 秒；
- 最大并发客户端连接数为 1024；
- 阻止回环、私网、链路本地、未指定和多播目标，使用 `-deny-private-ip=false` 关闭；
- 收到 `SIGINT` 或 `SIGTERM` 时关闭监听器；
- 用户名密码只用于认证，协议本身不提供加密，远程部署应通过 VPN、SSH 或 TLS 隧道保护。

常用参数：

```text
-addr                 监听地址，默认 127.0.0.1:8182
-auth                 username:password
SOCKS5_AUTH           可替代 -auth，避免凭据出现在进程参数中
-allow-no-auth        显式允许无认证模式
-deny-private-ip      阻止内网和本机目标，默认 true
-max-connections      最大并发连接数，默认 1024
-handshake-timeout    握手超时，默认 10s
-dial-timeout         DNS 和目标连接超时，默认 10s
-idle-timeout         代理连接无数据超时，默认 5m
```

## 开发验证

```bash
go test ./...
go test -race ./...
go vet ./...
go build ./...
```
