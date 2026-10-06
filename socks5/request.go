package socks5

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	ConnectCommand   = uint8(1)
	BindCommand      = uint8(2)
	AssociateCommand = uint8(3)
	ipv4Address      = uint8(1)
	fqdnAddress      = uint8(3)
	ipv6Address      = uint8(4)
)

const (
	successReply uint8 = iota
	serverFailure
	ruleFailure
	networkUnreachable
	hostUnreachable
	connectionRefused
	ttlExpired
	commandNotSupported
	addrTypeNotSupported
)

var (
	unrecognizedAddrType = fmt.Errorf("Unrecognized address type")
)

// AddressRewriter is used to rewrite a destination transparently
type AddressRewriter interface {
	Rewrite(ctx context.Context, request *Request) (context.Context, *AddrSpec)
}

// AddrSpec is used to return the target AddrSpec
// which may be specified as IPv4, IPv6, or a FQDN
type AddrSpec struct {
	FQDN string
	IP   net.IP
	Port int
}

func (a *AddrSpec) String() string {
	if a.FQDN != "" {
		return fmt.Sprintf("%s (%s):%d", a.FQDN, a.IP, a.Port)
	}
	return fmt.Sprintf("%s:%d", a.IP, a.Port)
}

// Address returns a string suitable to dial; prefer returning IP-based
// address, fallback to FQDN
func (a AddrSpec) Address() string {
	if 0 != len(a.IP) {
		return net.JoinHostPort(a.IP.String(), strconv.Itoa(a.Port))
	}
	return net.JoinHostPort(a.FQDN, strconv.Itoa(a.Port))
}

// A Request represents request received by a server
type Request struct {
	// Protocol version
	Version uint8
	// Requested command
	Command uint8
	// AuthContext provided during negotiation
	AuthContext *AuthContext
	// AddrSpec of the the network that sent the request
	RemoteAddr *AddrSpec
	// AddrSpec of the desired destination
	DestAddr *AddrSpec
	// AddrSpec of the actual destination (might be affected by rewrite)
	realDestAddr *AddrSpec
	bufConn      io.Reader
}

type conn interface {
	Write([]byte) (int, error)
	RemoteAddr() net.Addr
}

// NewRequest creates a new Request from the tcp connection
func NewRequest(bufConn io.Reader) (*Request, error) {
	// Read the version byte
	header := []byte{0, 0, 0}
	if _, err := io.ReadFull(bufConn, header); err != nil {
		return nil, fmt.Errorf("Failed to get command version: %v", err)
	}

	// Ensure we are compatible
	if header[0] != socks5Version {
		return nil, fmt.Errorf("Unsupported command version: %v", header[0])
	}
	if header[2] != 0 {
		return nil, fmt.Errorf("Invalid reserved byte: %v", header[2])
	}

	// Read in the destination address
	dest, err := readAddrSpec(bufConn)
	if err != nil {
		return nil, err
	}

	request := &Request{
		Version:  socks5Version,
		Command:  header[1],
		DestAddr: dest,
		bufConn:  bufConn,
	}

	return request, nil
}

// handleRequest is used for request processing after authentication
func (s *Server) handleRequest(req *Request, conn conn) error {
	ctx := context.Background()
	if s.lifecycle != nil {
		ctx = s.lifecycle
	}
	var cancel context.CancelFunc
	if s.config.DialTimeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, s.config.DialTimeout)
		defer cancel()
	}

	// Resolve the address if we have a FQDN
	dest := req.DestAddr
	if dest.FQDN != "" {
		ctx_, addr, err := s.config.Resolver.Resolve(ctx, dest.FQDN)
		if err != nil {
			if err := sendReply(conn, hostUnreachable, nil); err != nil {
				return fmt.Errorf("Failed to send reply: %v", err)
			}
			return fmt.Errorf("Failed to resolve destination '%v': %v", dest.FQDN, err)
		}
		ctx = ctx_
		if ctx == nil {
			ctx = context.Background()
		}
		dest.IP = addr
	}

	// Apply any address rewrites
	req.realDestAddr = req.DestAddr
	if s.config.Rewriter != nil {
		ctx, req.realDestAddr = s.config.Rewriter.Rewrite(ctx, req)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if req.realDestAddr == nil {
		if err := sendReply(conn, ruleFailure, nil); err != nil {
			return fmt.Errorf("failed to send reply: %v", err)
		}
		return fmt.Errorf("rewriter returned nil destination")
	}
	if s.config.DenyPrivateIPs && isPrivateIP(req.realDestAddr.IP) {
		if err := sendReply(conn, ruleFailure, nil); err != nil {
			return fmt.Errorf("failed to send reply: %v", err)
		}
		return fmt.Errorf("private destination %v blocked by rules", req.realDestAddr)
	}
	if req.realDestAddr.FQDN == "" && req.realDestAddr.IP == nil {
		if err := sendReply(conn, ruleFailure, nil); err != nil {
			return fmt.Errorf("failed to send reply: %v", err)
		}
		return fmt.Errorf("empty destination")
	}

	// Switch on the command
	switch req.Command {
	case ConnectCommand:
		return s.handleConnect(ctx, conn, req)
	case BindCommand:
		return s.handleBind(ctx, conn, req)
	case AssociateCommand:
		return s.handleAssociate(ctx, conn, req)
	default:
		if err := sendReply(conn, commandNotSupported, nil); err != nil {
			return fmt.Errorf("Failed to send reply: %v", err)
		}
		return fmt.Errorf("Unsupported command: %v", req.Command)
	}
}

// handleConnect is used to handle a connect command
func (s *Server) handleConnect(ctx context.Context, conn conn, req *Request) error {
	// Check if this is allowed
	if ctx_, ok := s.config.Rules.Allow(ctx, req); !ok {
		if err := sendReply(conn, ruleFailure, nil); err != nil {
			return fmt.Errorf("Failed to send reply: %v", err)
		}
		return fmt.Errorf("Connect to %v blocked by rules", req.DestAddr)
	} else {
		if ctx_ == nil {
			ctx_ = context.Background()
		}
		ctx = ctx_
	}
	if s.config.DialTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, s.config.DialTimeout)
		defer cancel()
	}

	// Attempt to connect
	dial := s.config.Dial
	if dial == nil {
		dialer := net.Dialer{Timeout: s.config.DialTimeout}
		dial = func(ctx context.Context, net_, addr string) (net.Conn, error) {
			return dialer.DialContext(ctx, net_, addr)
		}
	}
	target, err := dial(ctx, "tcp", req.realDestAddr.Address())
	if err == nil && target == nil {
		err = errors.New("dial returned a nil connection")
	}
	if err != nil {
		msg := err.Error()
		resp := hostUnreachable
		if strings.Contains(msg, "refused") {
			resp = connectionRefused
		} else if strings.Contains(msg, "network is unreachable") {
			resp = networkUnreachable
		}
		if err := sendReply(conn, resp, nil); err != nil {
			return fmt.Errorf("Failed to send reply: %v", err)
		}
		return fmt.Errorf("Connect to %v failed: %v", req.DestAddr, err)
	}
	defer target.Close()

	// Send success
	bind := AddrSpec{}
	if local, ok := target.LocalAddr().(*net.TCPAddr); ok {
		bind = AddrSpec{IP: local.IP, Port: local.Port}
	}
	if err := sendReply(conn, successReply, &bind); err != nil {
		return fmt.Errorf("Failed to send reply: %v", err)
	}

	// Start proxying
	errCh := make(chan error, 2)
	var deadlineMu sync.Mutex
	touch := func() {
		if s.config.IdleTimeout <= 0 {
			return
		}
		deadline := time.Now().Add(s.config.IdleTimeout)
		deadlineMu.Lock()
		_ = target.SetDeadline(deadline)
		if deadlineConn, ok := conn.(interface{ SetDeadline(time.Time) error }); ok {
			_ = deadlineConn.SetDeadline(deadline)
		}
		deadlineMu.Unlock()
	}
	touch()
	go proxy(target, req.bufConn, errCh, touch)
	go proxy(conn, target, errCh, touch)

	// Wait
	var firstErr error
	for i := 0; i < 2; i++ {
		e := <-errCh
		if e != nil {
			if firstErr == nil && !isClosedError(e) {
				firstErr = e
			}
			_ = target.Close()
			if closer, ok := conn.(io.Closer); ok {
				_ = closer.Close()
			}
		}
	}
	return firstErr
}

func isClosedError(err error) bool {
	if errors.Is(err, net.ErrClosed) {
		return true
	}
	return strings.Contains(err.Error(), "use of closed network connection")
}

// handleBind is used to handle a connect command
func (s *Server) handleBind(ctx context.Context, conn conn, req *Request) error {
	// Check if this is allowed
	if ctx_, ok := s.config.Rules.Allow(ctx, req); !ok {
		if err := sendReply(conn, ruleFailure, nil); err != nil {
			return fmt.Errorf("Failed to send reply: %v", err)
		}
		return fmt.Errorf("Bind to %v blocked by rules", req.DestAddr)
	} else {
		ctx = ctx_
	}

	// TODO: Support bind
	if err := sendReply(conn, commandNotSupported, nil); err != nil {
		return fmt.Errorf("Failed to send reply: %v", err)
	}
	return nil
}

// handleAssociate is used to handle a connect command
func (s *Server) handleAssociate(ctx context.Context, conn conn, req *Request) error {
	// Check if this is allowed
	if ctx_, ok := s.config.Rules.Allow(ctx, req); !ok {
		if err := sendReply(conn, ruleFailure, nil); err != nil {
			return fmt.Errorf("Failed to send reply: %v", err)
		}
		return fmt.Errorf("Associate to %v blocked by rules", req.DestAddr)
	} else {
		ctx = ctx_
	}

	// TODO: Support associate
	if err := sendReply(conn, commandNotSupported, nil); err != nil {
		return fmt.Errorf("Failed to send reply: %v", err)
	}
	return nil
}

// readAddrSpec is used to read AddrSpec.
// Expects an address type byte, follwed by the address and port
func readAddrSpec(r io.Reader) (*AddrSpec, error) {
	d := &AddrSpec{}

	// Get the address type
	addrType := []byte{0}
	if _, err := io.ReadFull(r, addrType); err != nil {
		return nil, err
	}

	// Handle on a per type basis
	switch addrType[0] {
	case ipv4Address:
		addr := make([]byte, 4)
		if _, err := io.ReadFull(r, addr); err != nil {
			return nil, err
		}
		d.IP = net.IP(addr)

	case ipv6Address:
		addr := make([]byte, 16)
		if _, err := io.ReadFull(r, addr); err != nil {
			return nil, err
		}
		d.IP = net.IP(addr)

	case fqdnAddress:
		if _, err := io.ReadFull(r, addrType); err != nil {
			return nil, err
		}
		addrLen := int(addrType[0])
		if addrLen == 0 {
			return nil, fmt.Errorf("empty hostname")
		}
		fqdn := make([]byte, addrLen)
		if _, err := io.ReadFull(r, fqdn); err != nil {
			return nil, err
		}
		d.FQDN = string(fqdn)

	default:
		return nil, unrecognizedAddrType
	}

	// Read the port
	port := []byte{0, 0}
	if _, err := io.ReadFull(r, port); err != nil {
		return nil, err
	}
	d.Port = (int(port[0]) << 8) | int(port[1])

	return d, nil
}

func isPrivateIP(ip net.IP) bool {
	if ip == nil || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() ||
		ip.IsUnspecified() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() {
		return true
	}
	reserved := []struct {
		network *net.IPNet
		name    string
	}{
		{network: mustCIDR("100.64.0.0/10"), name: "carrier-grade NAT"},
		{network: mustCIDR("192.0.0.0/24"), name: "IETF protocol assignments"},
		{network: mustCIDR("192.0.2.0/24"), name: "documentation"},
		{network: mustCIDR("198.18.0.0/15"), name: "benchmarking"},
		{network: mustCIDR("198.51.100.0/24"), name: "documentation"},
		{network: mustCIDR("203.0.113.0/24"), name: "documentation"},
	}
	for _, item := range reserved {
		if item.network.Contains(ip) {
			return true
		}
	}
	return false
}

func mustCIDR(value string) *net.IPNet {
	_, network, err := net.ParseCIDR(value)
	if err != nil {
		panic(err)
	}
	return network
}

// sendReply is used to send a reply message
func sendReply(w io.Writer, resp uint8, addr *AddrSpec) error {
	// Format the address
	var addrType uint8
	var addrBody []byte
	var addrPort uint16
	switch {
	case addr == nil:
		addrType = ipv4Address
		addrBody = []byte{0, 0, 0, 0}
		addrPort = 0

	case addr.FQDN != "":
		if len(addr.FQDN) > 255 {
			return fmt.Errorf("hostname is too long")
		}
		addrType = fqdnAddress
		addrBody = append([]byte{byte(len(addr.FQDN))}, addr.FQDN...)
		addrPort = uint16(addr.Port)

	case addr.IP.To4() != nil:
		addrType = ipv4Address
		addrBody = []byte(addr.IP.To4())
		addrPort = uint16(addr.Port)

	case addr.IP.To16() != nil:
		addrType = ipv6Address
		addrBody = []byte(addr.IP.To16())
		addrPort = uint16(addr.Port)

	default:
		return fmt.Errorf("Failed to format address: %v", addr)
	}

	// Format the message
	msg := make([]byte, 6+len(addrBody))
	msg[0] = socks5Version
	msg[1] = resp
	msg[2] = 0 // Reserved
	msg[3] = addrType
	copy(msg[4:], addrBody)
	msg[4+len(addrBody)] = byte(addrPort >> 8)
	msg[4+len(addrBody)+1] = byte(addrPort & 0xff)

	// Send the message
	return writeFull(w, msg)
}

func writeFull(w io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := w.Write(data)
		if n > 0 {
			data = data[n:]
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

type closeWriter interface {
	CloseWrite() error
}

// proxy is used to suffle data from src to destination, and sends errors
// down a dedicated channel
func proxy(dst io.Writer, src io.Reader, errCh chan error, touch func()) {
	buf := proxyBufferPool.Get().([]byte)
	reader := io.Reader(src)
	if touch != nil {
		reader = activityReader{Reader: src, touch: touch}
	}
	_, err := io.CopyBuffer(dst, reader, buf)
	proxyBufferPool.Put(buf)
	if tcpConn, ok := dst.(closeWriter); ok {
		tcpConn.CloseWrite()
	}
	errCh <- err
}

type activityReader struct {
	io.Reader
	touch func()
}

func (r activityReader) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	if n > 0 {
		r.touch()
	}
	return n, err
}

var proxyBufferPool = sync.Pool{New: func() interface{} {
	return make([]byte, 32*1024)
}}
