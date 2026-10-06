package socks5

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"log"
	"net"
	"os"
	"testing"
	"time"
)

func TestSOCKS5_Connect(t *testing.T) {
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

	// Create a socks server
	creds := StaticCredentials{
		"foo": "bar",
	}
	cator := UserPassAuthenticator{Credentials: creds}
	conf := &Config{
		AuthMethods:     []Authenticator{cator},
		AllowPrivateIPs: true,
		Logger:          log.New(os.Stdout, "", log.LstdFlags),
	}
	serv, err := New(conf)
	if err != nil {
		t.Errorf("err: %v", err)
	}

	// Start listening on an ephemeral port to keep the test isolated.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		if err := serv.Serve(listener); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Errorf("err: %v", err)
		}
	}()

	// Get a local conn
	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Errorf("err: %v", err)
	}

	// Connect, auth and connec to local
	req := bytes.NewBuffer(nil)
	req.Write([]byte{5})
	req.Write([]byte{2, NoAuth, UserPassAuth})
	req.Write([]byte{1, 3, 'f', 'o', 'o', 3, 'b', 'a', 'r'})
	req.Write([]byte{5, 1, 0, 1, 127, 0, 0, 1})

	port := []byte{0, 0}
	binary.BigEndian.PutUint16(port, uint16(lAddr.Port))
	req.Write(port)

	// Send a ping
	req.Write([]byte("ping"))

	// Send all the bytes
	conn.Write(req.Bytes())

	// Verify response
	expected := []byte{
		socks5Version, UserPassAuth,
		1, authSuccess,
		5,
		0,
		0,
		1,
		127, 0, 0, 1,
		0, 0,
		'p', 'o', 'n', 'g',
	}
	out := make([]byte, len(expected))

	conn.SetDeadline(time.Now().Add(time.Second))
	if _, err := io.ReadAtLeast(conn, out, len(out)); err != nil {
		t.Errorf("err: %v", err)
	}

	// Ignore the port
	out[12] = 0
	out[13] = 0

	if !bytes.Equal(out, expected) {
		t.Fatalf("bad: %v", out)
	}
}

func TestServeConnHandshakeTimeout(t *testing.T) {
	server, err := New(&Config{AllowNoAuth: true, HandshakeTimeout: 10 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	client, serverConn := net.Pipe()
	defer client.Close()

	done := make(chan error, 1)
	go func() { done <- server.ServeConn(serverConn) }()

	select {
	case <-time.After(time.Second):
		t.Fatal("ServeConn did not time out")
	case err := <-done:
		if err == nil {
			t.Fatal("expected handshake timeout error")
		}
	}
}
