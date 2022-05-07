package main

import (
	"flag"
	"socks5-server/socks5"
	"strings"
)

var addr, auth string

func init() {
	flag.StringVar(&addr, "addr", "0.0.0.0:8182", "listen address.eg: 127.0.0.1:8080")
	flag.StringVar(&auth, "auth", "", "listen auth.eg: username:password")
}

func main() {
	flag.Parse()

	conf := &socks5.Config{}
	if auth != "" {
		s := strings.Split(auth, ":")
		cre := socks5.UserPassAuthenticator{
			Credentials: socks5.StaticCredentials{s[0]:s[1]},
		}
		conf = &socks5.Config{Credentials: cre.Credentials}
	}

	server, err := socks5.New(conf)
	if err != nil {
		panic(err)
	}

	// Create SOCKS5 proxy on localhost port 8000
	if err := server.ListenAndServe("tcp", addr); err != nil {
		panic(err)
	}
}
