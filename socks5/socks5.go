package socks5

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

const (
	socks5Version = uint8(5)
)

// Config is used to setup and configure a Server
type Config struct {
	// AuthMethods can be provided to implement custom authentication
	// By default, "auth-less" mode is enabled.
	// For password-based auth use UserPassAuthenticator.
	AuthMethods []Authenticator

	// If provided, username/password authentication is enabled,
	// by appending a UserPassAuthenticator to AuthMethods. If not provided,
	// and AllowNoAuth is false, New returns an error.
	Credentials CredentialStore

	// AllowNoAuth explicitly enables the unauthenticated method when no
	// credentials or custom authentication methods are configured.
	AllowNoAuth bool

	// Resolver can be provided to do custom name resolution.
	// Defaults to DNSResolver if not provided.
	Resolver NameResolver

	// Rules is provided to enable custom logic around permitting
	// various commands. If not provided, PermitAll is used.
	Rules RuleSet

	// Rewriter can be used to transparently rewrite addresses.
	// This is invoked before the RuleSet is invoked.
	// Defaults to NoRewrite.
	Rewriter AddressRewriter

	// BindIP is used for bind or udp associate
	BindIP net.IP

	// Logger can be used to provide a custom log target.
	// Defaults to stdout.
	Logger *log.Logger

	// Optional function for dialing out
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)

	// HandshakeTimeout bounds SOCKS negotiation and request parsing.
	HandshakeTimeout time.Duration

	// DialTimeout bounds outbound TCP connection establishment.
	DialTimeout time.Duration

	// IdleTimeout bounds inactivity while proxying. Zero uses five minutes.
	IdleTimeout time.Duration

	// MaxConnections limits active client connections. Zero uses the default.
	MaxConnections int

	// DenyPrivateIPs blocks loopback, private, link-local, multicast and
	// unspecified destination addresses after DNS resolution and rewriting.
	DenyPrivateIPs bool

	// AllowPrivateIPs disables the default private/reserved destination block.
	AllowPrivateIPs bool
}

// Server is reponsible for accepting connections and handling
// the details of the SOCKS5 protocol
type Server struct {
	config      *Config
	authMethods map[uint8]Authenticator
	authOrder   []uint8
	connections chan struct{}
	closed      uint32
	activeMu    sync.Mutex
	active      map[net.Conn]struct{}
	lifecycle   context.Context
	cancel      context.CancelFunc
}

// New creates a new Server and potentially returns an error
func New(conf *Config) (*Server, error) {
	if conf == nil {
		conf = &Config{}
	}
	if conf.HandshakeTimeout <= 0 {
		conf.HandshakeTimeout = 10 * time.Second
	}
	if conf.DialTimeout <= 0 {
		conf.DialTimeout = 10 * time.Second
	}
	if conf.IdleTimeout <= 0 {
		conf.IdleTimeout = 5 * time.Minute
	}
	if conf.MaxConnections <= 0 {
		conf.MaxConnections = 1024
	}
	// Ensure we have at least one authentication method enabled.
	if len(conf.AuthMethods) == 0 {
		if conf.Credentials != nil {
			conf.AuthMethods = []Authenticator{&UserPassAuthenticator{conf.Credentials}}
		} else if conf.AllowNoAuth {
			conf.AuthMethods = []Authenticator{&NoAuthAuthenticator{}}
		} else {
			return nil, errors.New("authentication is required; configure Credentials/AuthMethods or set AllowNoAuth")
		}
	} else if conf.Credentials != nil {
		userPassConfigured := false
		for _, method := range conf.AuthMethods {
			if method != nil && method.GetCode() == UserPassAuth {
				userPassConfigured = true
				break
			}
			if method != nil && method.GetCode() == NoAuth {
				return nil, errors.New("NoAuth cannot be combined with Credentials")
			}
		}
		if !userPassConfigured {
			conf.AuthMethods = append([]Authenticator{&UserPassAuthenticator{conf.Credentials}}, conf.AuthMethods...)
		}
	}
	if !conf.AllowPrivateIPs {
		conf.DenyPrivateIPs = true
	}

	// Ensure we have a DNS resolver
	if conf.Resolver == nil {
		conf.Resolver = DNSResolver{}
	}

	// Ensure we have a rule set
	if conf.Rules == nil {
		conf.Rules = PermitAll()
	}

	// Ensure we have a log target
	if conf.Logger == nil {
		conf.Logger = log.New(os.Stdout, "", log.LstdFlags)
	}

	lifecycle, cancel := context.WithCancel(context.Background())
	server := &Server{
		config:      conf,
		connections: make(chan struct{}, conf.MaxConnections),
		active:      make(map[net.Conn]struct{}),
		lifecycle:   lifecycle,
		cancel:      cancel,
	}

	server.authMethods = make(map[uint8]Authenticator)

	for _, a := range conf.AuthMethods {
		if a == nil {
			return nil, errors.New("nil authentication method")
		}
		server.authMethods[a.GetCode()] = a
		server.authOrder = append(server.authOrder, a.GetCode())
	}

	return server, nil
}

// ListenAndServe is used to create a listener and serve on it
func (s *Server) ListenAndServe(network, addr string) error {
	l, err := net.Listen(network, addr)
	if err != nil {
		return err
	}
	defer l.Close()
	return s.Serve(l)
}

// Serve is used to serve connections from a listener
func (s *Server) Serve(l net.Listener) error {
	if s.connections == nil {
		maxConnections := s.config.MaxConnections
		if maxConnections <= 0 {
			maxConnections = 1024
		}
		s.connections = make(chan struct{}, maxConnections)
	}
	for {
		conn, err := l.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) || atomic.LoadUint32(&s.closed) == 1 {
				return err
			}
			if netErr, ok := err.(net.Error); ok && netErr.Temporary() {
				time.Sleep(5 * time.Millisecond)
				continue
			}
			return err
		}
		select {
		case s.connections <- struct{}{}:
			go func() {
				defer func() {
					<-s.connections
				}()
				_ = s.ServeConn(conn)
			}()
		default:
			_ = conn.Close()
		}
	}
}

// Close marks the server as shutting down. The listener owned by the caller
// must still be closed to unblock Serve.
func (s *Server) Close() {
	atomic.StoreUint32(&s.closed, 1)
	if s.cancel != nil {
		s.cancel()
	}
	s.activeMu.Lock()
	connections := make([]net.Conn, 0, len(s.active))
	for conn := range s.active {
		connections = append(connections, conn)
	}
	s.activeMu.Unlock()
	for _, conn := range connections {
		_ = conn.Close()
	}
}

func (s *Server) trackIfOpen(conn net.Conn) bool {
	s.activeMu.Lock()
	defer s.activeMu.Unlock()
	if atomic.LoadUint32(&s.closed) == 1 {
		return false
	}
	if s.active == nil {
		s.active = make(map[net.Conn]struct{})
	}
	s.active[conn] = struct{}{}
	return true
}

func (s *Server) untrack(conn net.Conn) {
	s.activeMu.Lock()
	delete(s.active, conn)
	s.activeMu.Unlock()
}

// ServeConn is used to serve a single connection.
func (s *Server) ServeConn(conn net.Conn) error {
	if !s.trackIfOpen(conn) {
		_ = conn.Close()
		return net.ErrClosed
	}
	defer s.untrack(conn)
	defer conn.Close()
	if s.config.HandshakeTimeout > 0 {
		_ = conn.SetDeadline(time.Now().Add(s.config.HandshakeTimeout))
		defer conn.SetDeadline(time.Time{})
	}
	bufConn := bufio.NewReader(conn)

	// Read the version byte
	version := []byte{0}
	if _, err := io.ReadFull(bufConn, version); err != nil {
		s.config.Logger.Printf("[ERR] socks: Failed to get version byte: %v", err)
		return err
	}

	// Ensure we are compatible
	if version[0] != socks5Version {
		err := fmt.Errorf("Unsupported SOCKS version: %v", version)
		s.config.Logger.Printf("[ERR] socks: %v", err)
		return err
	}

	// Authenticate the connection
	authContext, err := s.authenticate(conn, bufConn)
	if err != nil {
		err = fmt.Errorf("Failed to authenticate: %v", err)
		s.config.Logger.Printf("[ERR] socks: %v", err)
		return err
	}

	request, err := NewRequest(bufConn)
	if err != nil {
		if err == unrecognizedAddrType {
			if err := sendReply(conn, addrTypeNotSupported, nil); err != nil {
				return fmt.Errorf("Failed to send reply: %v", err)
			}
		}
		return fmt.Errorf("Failed to read destination address: %v", err)
	}

	request.AuthContext = authContext
	_ = conn.SetDeadline(time.Time{})
	if client, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		request.RemoteAddr = &AddrSpec{IP: client.IP, Port: client.Port}
	}

	// Process the client request
	if err := s.handleRequest(request, conn); err != nil {
		err = fmt.Errorf("Failed to handle request: %v", err)
		s.config.Logger.Printf("[ERR] socks: %v", err)
		return err
	}

	return nil
}
