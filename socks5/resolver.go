package socks5

import (
	"context"
	"fmt"
	"net"
)

// NameResolver is used to implement custom name resolution
type NameResolver interface {
	Resolve(ctx context.Context, name string) (context.Context, net.IP, error)
}

// DNSResolver uses the system DNS to resolve host names
type DNSResolver struct{}

func (d DNSResolver) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	addrs, err := net.DefaultResolver.LookupIP(ctx, "ip", name)
	if err != nil {
		return ctx, nil, err
	}
	if len(addrs) == 0 {
		return ctx, nil, fmt.Errorf("no addresses found for %q", name)
	}
	return ctx, addrs[0], nil
}
