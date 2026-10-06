package socks5

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log"
	"net"
	"testing"
	"time"
)

// listenTestTCP 使用系统分配端口，所有监听器在测试结束时收回。
func listenTestTCP(t *testing.T) net.Listener {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l
}

func testServer(t *testing.T, conf Config) *Server {
	t.Helper()
	conf.Logger = log.New(io.Discard, "", 0)
	if len(conf.AuthMethods) == 0 && conf.Credentials == nil {
		conf.AllowNoAuth = true
	}
	conf.AllowPrivateIPs = true
	s, err := New(&conf)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func startTestServer(t *testing.T, s *Server) net.Listener {
	t.Helper()
	l := listenTestTCP(t)
	done := make(chan error, 1)
	go func() { done <- s.Serve(l) }()
	t.Cleanup(func() {
		s.Close()
		_ = l.Close()
		select {
		case err := <-done:
			if err != nil && !errors.Is(err, net.ErrClosed) {
				t.Error(err)
			}
		case <-time.After(2 * time.Second):
			t.Error("Serve did not stop")
		}
	})
	return l
}

// openTestTunnel 使用真实 TCP 完成协议协商，覆盖认证后 CONNECT 完整路径。
func openTestTunnel(t *testing.T, proxyAddr, targetAddr string) *net.TCPConn {
	t.Helper()
	raw, err := net.DialTimeout("tcp", proxyAddr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	client := raw.(*net.TCPConn)
	t.Cleanup(func() { _ = client.Close() })
	_ = client.SetDeadline(time.Now().Add(2 * time.Second))
	if err := writeFull(client, []byte{5, 1, NoAuth}); err != nil {
		t.Fatal(err)
	}
	var method [2]byte
	if _, err := io.ReadFull(client, method[:]); err != nil || method != [2]byte{5, NoAuth} {
		t.Fatalf("authentication: %v, %v", method, err)
	}
	dest, err := net.ResolveTCPAddr("tcp", targetAddr)
	if err != nil {
		t.Fatal(err)
	}
	request := []byte{5, ConnectCommand, 0, ipv4Address}
	request = append(request, dest.IP.To4()...)
	request = append(request, byte(dest.Port>>8), byte(dest.Port))
	if err := writeFull(client, request); err != nil {
		t.Fatal(err)
	}
	var reply [3]byte
	if _, err := io.ReadFull(client, reply[:]); err != nil || reply != [3]byte{5, successReply, 0} {
		t.Fatalf("connect: %v, %v", reply, err)
	}
	if _, err := readAddrSpec(client); err != nil {
		t.Fatal(err)
	}
	return client
}

func TestCloseStopsDirectServeConn(t *testing.T) {
	s := testServer(t, Config{})
	client, peer := net.Pipe()
	defer client.Close()
	done := make(chan error, 1)
	go func() { done <- s.ServeConn(peer) }()
	_ = client.SetDeadline(time.Now().Add(time.Second))
	if err := writeFull(client, []byte{5, 1, NoAuth}); err != nil {
		t.Fatal(err)
	}
	var method [2]byte
	if _, err := io.ReadFull(client, method[:]); err != nil {
		t.Fatal(err)
	}
	s.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Close left direct ServeConn blocked")
	}
}

func TestCloseStopsListener(t *testing.T) {
	s := testServer(t, Config{})
	l := listenTestTCP(t)
	done := make(chan error, 1)
	go func() { done <- s.Serve(l) }()
	// 第一次协商确保 Serve 已经登记监听器，不依赖休眠。
	c, err := net.DialTimeout("tcp", l.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(time.Second))
	_ = writeFull(c, []byte{5, 1, NoAuth})
	var method [2]byte
	if _, err := io.ReadFull(c, method[:]); err != nil {
		t.Fatal(err)
	}
	s.Close()
	_ = l.Close()
	select {
	case err := <-done:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("expected closed listener, got %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close left Accept blocked")
	}
}

func TestCloseCancelsOutboundDial(t *testing.T) {
	started := make(chan struct{})
	s := testServer(t, Config{Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		close(started)
		<-ctx.Done()
		return nil, ctx.Err()
	}})
	client, peer := net.Pipe()
	defer client.Close()
	done := make(chan error, 1)
	go func() { done <- s.ServeConn(peer) }()
	_ = client.SetDeadline(time.Now().Add(time.Second))
	_ = writeFull(client, []byte{5, 1, NoAuth})
	var method [2]byte
	if _, err := io.ReadFull(client, method[:]); err != nil {
		t.Fatal(err)
	}
	_ = writeFull(client, []byte{5, 1, 0, 1, 8, 8, 8, 8, 0, 80})
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("dial never started")
	}
	s.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Close did not cancel Dial context")
	}
}

func TestTunnelHalfClosePreservesResponse(t *testing.T) {
	target := listenTestTCP(t)
	done := make(chan error, 1)
	go func() {
		c, err := target.Accept()
		if err != nil {
			done <- err
			return
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(2 * time.Second))
		data, err := io.ReadAll(c)
		if err == nil && !bytes.Equal(data, []byte("request")) {
			err = errors.New("bad payload")
		}
		if err == nil {
			err = writeFull(c, []byte("response"))
		}
		done <- err
	}()
	s := testServer(t, Config{})
	l := startTestServer(t, s)
	c := openTestTunnel(t, l.Addr().String(), target.Addr().String())
	if err := writeFull(c, []byte("request")); err != nil {
		t.Fatal(err)
	}
	if err := c.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(c)
	if err != nil || string(data) != "response" {
		t.Fatalf("half-close response %q: %v", data, err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestTunnelIdleTimeoutClosesBothEnds(t *testing.T) {
	target := listenTestTCP(t)
	done := make(chan error, 1)
	go func() {
		c, err := target.Accept()
		if err != nil {
			done <- err
			return
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(time.Second))
		_, err = io.ReadAll(c)
		done <- err
	}()
	s := testServer(t, Config{IdleTimeout: 30 * time.Millisecond})
	l := startTestServer(t, s)
	c := openTestTunnel(t, l.Addr().String(), target.Addr().String())
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("idle client remained open")
	}
	if err := <-done; err != nil {
		t.Fatalf("target did not receive EOF: %v", err)
	}
}

func TestMaxConnectionsRejectsAndReleases(t *testing.T) {
	s := testServer(t, Config{MaxConnections: 1, HandshakeTimeout: time.Second})
	l := startTestServer(t, s)
	first, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	_ = first.SetDeadline(time.Now().Add(time.Second))
	_ = writeFull(first, []byte{5, 1, NoAuth})
	var method [2]byte
	if _, err := io.ReadFull(first, method[:]); err != nil {
		t.Fatal(err)
	}
	second, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	_ = second.SetDeadline(time.Now().Add(time.Second))
	if _, err := second.Read(make([]byte, 1)); err == nil {
		t.Fatal("connection limit not enforced")
	}
	_ = first.Close()
	// 等额度释放后验证下一个真实客户端可以完成协商。
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		c, err := net.Dial("tcp", l.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		_ = c.SetDeadline(time.Now().Add(100 * time.Millisecond))
		err = writeFull(c, []byte{5, 1, NoAuth})
		if err == nil {
			_, err = io.ReadFull(c, method[:])
		}
		_ = c.Close()
		if err == nil {
			return
		}
	}
	t.Fatal("connection capacity was not released")
}
