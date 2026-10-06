package socks5

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"testing"
)

type MockConn struct {
	buf bytes.Buffer
}

func (m *MockConn) Write(b []byte) (int, error) {
	return m.buf.Write(b)
}

func (m *MockConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: []byte{127, 0, 0, 1}, Port: 65432}
}

func TestRequest_Connect(t *testing.T) {
	// Create a local listener
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Errorf("err: %v", err)
	}
	defer l.Close()
	go func() {
		conn, err := l.Accept()
		if err != nil {
			t.Errorf("err: %v", err)
		}
		defer conn.Close()

		buf := make([]byte, 4)
		if _, err := io.ReadAtLeast(conn, buf, 4); err != nil {
			t.Errorf("err: %v", err)
		}

		if !bytes.Equal(buf, []byte("ping")) {
			t.Errorf("bad: %v", buf)
		}
		conn.Write([]byte("pong"))
	}()
	lAddr := l.Addr().(*net.TCPAddr)

	// Make server
	s := &Server{config: &Config{
		Rules:    PermitAll(),
		Resolver: DNSResolver{},
		Logger:   log.New(os.Stdout, "", log.LstdFlags),
	}}

	// Create the connect request
	buf := bytes.NewBuffer(nil)
	buf.Write([]byte{5, 1, 0, 1, 127, 0, 0, 1})

	port := []byte{0, 0}
	binary.BigEndian.PutUint16(port, uint16(lAddr.Port))
	buf.Write(port)

	// Send a ping
	buf.Write([]byte("ping"))

	// Handle the request
	resp := &MockConn{}
	req, err := NewRequest(buf)
	if err != nil {
		t.Errorf("err: %v", err)
	}

	if err := s.handleRequest(req, resp); err != nil {
		t.Errorf("err: %v", err)
	}

	// Verify response
	out := resp.buf.Bytes()
	expected := []byte{
		5,
		0,
		0,
		1,
		127, 0, 0, 1,
		0, 0,
		'p', 'o', 'n', 'g',
	}

	// Ignore the port for both
	out[8] = 0
	out[9] = 0

	if !bytes.Equal(out, expected) {
		t.Fatalf("bad: %v %v", out, expected)
	}
}

func TestRequest_Connect_RuleFail(t *testing.T) {
	// Make server
	s := &Server{config: &Config{
		Rules:    PermitNone(),
		Resolver: DNSResolver{},
		Logger:   log.New(os.Stdout, "", log.LstdFlags),
	}}

	// Create the connect request
	buf := bytes.NewBuffer(nil)
	buf.Write([]byte{5, 1, 0, 1, 127, 0, 0, 1})

	port := []byte{0, 0}
	binary.BigEndian.PutUint16(port, 1)
	buf.Write(port)

	// Send a ping
	buf.Write([]byte("ping"))

	// Handle the request
	resp := &MockConn{}
	req, err := NewRequest(buf)
	if err != nil {
		t.Errorf("err: %v", err)
	}

	if err := s.handleRequest(req, resp); !strings.Contains(err.Error(), "blocked by rules") {
		t.Errorf("err: %v", err)
	}

	// Verify response
	out := resp.buf.Bytes()
	expected := []byte{
		5,
		2,
		0,
		1,
		0, 0, 0, 0,
		0, 0,
	}

	if !bytes.Equal(out, expected) {
		t.Fatalf("bad: %v %v", out, expected)
	}
}

func TestNewRequestRejectsNonZeroReservedByte(t *testing.T) {
	buf := bytes.NewBuffer([]byte{5, ConnectCommand, 1, ipv4Address, 127, 0, 0, 1, 0, 80})
	if _, err := NewRequest(buf); err == nil {
		t.Fatal("expected non-zero reserved byte to be rejected")
	}
}

func TestReadAddrSpecRejectsEmptyHostname(t *testing.T) {
	buf := bytes.NewBuffer([]byte{fqdnAddress, 0, 0, 80})
	if _, err := readAddrSpec(buf); err == nil {
		t.Fatal("expected empty hostname to be rejected")
	}
}

func TestHandleRequestBlocksPrivateDestinationWhenConfigured(t *testing.T) {
	server := &Server{config: &Config{
		Rules:          PermitAll(),
		Resolver:       DNSResolver{},
		DenyPrivateIPs: true,
		Logger:         log.New(io.Discard, "", 0),
	}}
	request := &Request{
		Version:  socks5Version,
		Command:  ConnectCommand,
		DestAddr: &AddrSpec{IP: net.ParseIP("127.0.0.1"), Port: 80},
		bufConn:  bytes.NewReader(nil),
	}
	conn := &MockConn{}
	if err := server.handleRequest(request, conn); err == nil || !strings.Contains(err.Error(), "private") {
		t.Fatalf("expected private destination to be blocked, got %v", err)
	}
	if got := conn.buf.Bytes(); len(got) < 2 || got[1] != ruleFailure {
		t.Fatalf("expected rule failure reply, got %v", got)
	}
}

func TestNewRequiresAuthenticationByDefault(t *testing.T) {
	if _, err := New(&Config{}); err == nil {
		t.Fatal("expected authentication to be required by default")
	}
}

func TestCredentialsCannotEnableNoAuth(t *testing.T) {
	_, err := New(&Config{
		Credentials: StaticCredentials{"user": "password"},
		AuthMethods: []Authenticator{NoAuthAuthenticator{}},
	})
	if err == nil {
		t.Fatal("expected credentials and NoAuth conflict to be rejected")
	}
}

func TestHandleConnectRejectsNilDialConnection(t *testing.T) {
	server, err := New(&Config{
		Credentials: StaticCredentials{"user": "password"},
		Dial:        func(context.Context, string, string) (net.Conn, error) { return nil, nil },
		Logger:      log.New(io.Discard, "", 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	request := &Request{Command: ConnectCommand, DestAddr: &AddrSpec{IP: net.ParseIP("8.8.8.8"), Port: 53}, bufConn: bytes.NewReader(nil)}
	if err := server.handleRequest(request, &MockConn{}); err == nil || !strings.Contains(err.Error(), "nil connection") {
		t.Fatalf("expected nil dial connection error, got %v", err)
	}
}
