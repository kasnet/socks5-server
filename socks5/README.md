go-socks5 [![Build Status](https://travis-ci.org/armon/go-socks5.png)](https://travis-ci.org/armon/go-socks5)
=========

Provides the `socks5` package that implements a [SOCKS5 server](http://en.wikipedia.org/wiki/SOCKS).
SOCKS (Secure Sockets) is used to route traffic between a client and server through
an intermediate proxy layer. This can be used to bypass firewalls or NATs.

Feature
=======

The package has the following features:
* "No Auth" mode
* User/Password authentication
* Support for the CONNECT command
* Rules to do granular filtering of commands
* Custom DNS resolution
* Unit tests

TODO
====

The package still needs the following:
* Support for the BIND command
* Support for the ASSOCIATE command


Example
=======

命令行程序默认只监听本机并要求显式配置认证。库层 API 默认同样要求认证：使用 `Credentials` 或 `AuthMethods`；只有明确设置 `AllowNoAuth: true` 才会启用无认证。生产环境应设置 `HandshakeTimeout`、`DialTimeout`、`IdleTimeout`、`MaxConnections`，并保留 `DenyPrivateIPs`。

Below is a simple example of usage

```go
// Create a SOCKS5 server
conf := &socks5.Config{
  Credentials: socks5.StaticCredentials{"user": "password"},
}
server, err := socks5.New(conf)
if err != nil {
  panic(err)
}

// Create SOCKS5 proxy on localhost port 8000
if err := server.ListenAndServe("tcp", "127.0.0.1:8000"); err != nil {
  panic(err)
}
```
