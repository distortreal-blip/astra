package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strings"

	"astra/internal/config"
	"astra/internal/transport"
)

const defaultAddr = "127.0.0.1:9443"

func main() {
	configPath := flag.String("config", getenv("ASTRA_CONFIG", "configs/astra-relay.json"), "config path")
	flagAddr := flag.String("addr", "", "RELAY_ADDR")
	flagTransport := flag.String("transport", "", "RELAY_TRANSPORT")
	flagNext := flag.String("next", "", "RELAY_NEXT_ADDR")
	flagNextTransport := flag.String("next-transport", "", "RELAY_NEXT_TRANSPORT")
	flag.Parse()
	if err := config.ApplyEnvFile(*configPath); err != nil {
		panic(err)
	}
	config.ApplyOverrides(map[string]string{
		"RELAY_ADDR":           *flagAddr,
		"RELAY_TRANSPORT":      *flagTransport,
		"RELAY_NEXT_ADDR":      *flagNext,
		"RELAY_NEXT_TRANSPORT": *flagNextTransport,
	})
	addr := getenv("RELAY_ADDR", defaultAddr)
	next := getenv("RELAY_NEXT_ADDR", getenv("EXIT_ADDR", ""))
	if next == "" {
		panic("RELAY_NEXT_ADDR or EXIT_ADDR required")
	}
	ln, err := listenTransport(getenv("RELAY_TRANSPORT", "tcp"), addr)
	if err != nil {
		panic(err)
	}
	fmt.Println("Astra Relay listening on", ln.Addr().String())
	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		go handle(conn, next)
	}
}

func handle(conn net.Conn, next string) {
	defer conn.Close()
	up, err := dialTransport(getenv("RELAY_NEXT_TRANSPORT", "tcp"), next)
	if err != nil {
		return
	}
	defer up.Close()
	go io.Copy(up, conn)
	io.Copy(conn, up)
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func listenTransport(name, addr string) (net.Listener, error) {
	switch name {
	case "rudp":
		return transport.ReliableUDPTransport{}.Listen(addr)
	case "udp":
		return transport.UDPTransport{}.Listen(addr)
	case "tls":
		alpn := getenv("RELAY_TLS_ALPN", "h2")
		alpns := strings.Split(alpn, ",")
		for i := range alpns {
			alpns[i] = strings.TrimSpace(alpns[i])
		}
		return transport.TLSTransport{ALPN: alpns, Profile: "chrome"}.Listen(addr)
	default:
		return transport.TCPTransport{}.Listen(addr)
	}
}

func dialTransport(name, addr string) (net.Conn, error) {
	switch name {
	case "rudp":
		return transport.ReliableUDPTransport{}.Dial(context.Background(), addr)
	case "udp":
		return transport.UDPTransport{}.Dial(context.Background(), addr)
	case "tls":
		return transport.TLSTransport{ServerName: getenv("RELAY_TLS_HOST", "astra.local"), ALPN: []string{"h2", "http/1.1"}, Profile: "chrome"}.Dial(context.Background(), addr)
	default:
		return transport.TCPTransport{}.Dial(context.Background(), addr)
	}
}
