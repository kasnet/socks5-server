package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"socks5-server/socks5"
	"strings"
	"syscall"
	"time"
)

var (
	addr          string
	auth          string
	allowNoAuth   bool
	denyPrivateIP bool
	maxConn       int
	handshakeTTL  time.Duration
	dialTTL       time.Duration
	idleTTL       time.Duration
)

func init() {
	flag.StringVar(&addr, "addr", "127.0.0.1:8182", "监听地址，例如 127.0.0.1:8080")
	flag.StringVar(&auth, "auth", "", "认证信息，格式为 username:password；密码可以包含冒号")
	flag.BoolVar(&allowNoAuth, "allow-no-auth", false, "显式允许无认证代理（仅建议用于受信任内网）")
	flag.BoolVar(&denyPrivateIP, "deny-private-ip", true, "阻止访问回环、私网、链路本地和多播地址")
	flag.IntVar(&maxConn, "max-connections", 1024, "最大并发连接数")
	flag.DurationVar(&handshakeTTL, "handshake-timeout", 10*time.Second, "SOCKS 握手超时")
	flag.DurationVar(&dialTTL, "dial-timeout", 10*time.Second, "目标连接和 DNS 超时")
	flag.DurationVar(&idleTTL, "idle-timeout", 5*time.Minute, "代理连接无数据超时")
}

func main() {
	flag.Parse()

	conf := &socks5.Config{
		HandshakeTimeout: handshakeTTL,
		DialTimeout:      dialTTL,
		IdleTimeout:      idleTTL,
		MaxConnections:   maxConn,
		DenyPrivateIPs:   denyPrivateIP,
		AllowPrivateIPs:  !denyPrivateIP,
		AllowNoAuth:      allowNoAuth,
	}
	if auth == "" {
		auth = os.Getenv("SOCKS5_AUTH")
	}
	if auth == "" {
		if !allowNoAuth {
			log.Fatal("默认拒绝无认证启动；如确需使用，请显式传入 -allow-no-auth")
		}
	} else {
		credentials, err := parseAuth(auth)
		if err != nil {
			log.Fatalf("无效的 -auth 参数: %v", err)
		}
		conf.Credentials = credentials
	}

	server, err := socks5.New(conf)
	if err != nil {
		log.Fatal(err)
	}

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-signals
		server.Close()
		_ = listener.Close()
	}()

	if err := server.Serve(listener); err != nil && !errors.Is(err, net.ErrClosed) {
		log.Fatal(err)
	}
}

func parseAuth(value string) (socks5.StaticCredentials, error) {
	parts := strings.SplitN(value, ":", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return nil, fmt.Errorf("需要非空的 username:password")
	}
	return socks5.StaticCredentials{parts[0]: parts[1]}, nil
}
