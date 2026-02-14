package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync/atomic"

	"astra/internal/config"
	"astra/internal/transport"
	"astra/internal/tun"
)

const defaultAddr = "127.0.0.1:10443"

func main() {
	configPath := flag.String("config", getenv("ASTRA_CONFIG", "configs/astra-exit.json"), "config path")
	flagAddr := flag.String("addr", "", "EXIT_ADDR")
	flagTransport := flag.String("transport", "", "EXIT_TRANSPORT")
	flagUp := flag.String("upstream", "", "EXIT_UPSTREAM_ADDR")
	flagUpTransport := flag.String("upstream-transport", "", "EXIT_UPSTREAM_TRANSPORT")
	flagDNSOnly := flag.String("dns-only", "", "EXIT_DNS_ONLY")
	flag.Parse()
	if err := config.ApplyEnvFile(*configPath); err != nil {
		panic(err)
	}
	config.ApplyOverrides(map[string]string{
		"EXIT_ADDR":               *flagAddr,
		"EXIT_TRANSPORT":          *flagTransport,
		"EXIT_UPSTREAM_ADDR":      *flagUp,
		"EXIT_UPSTREAM_TRANSPORT": *flagUpTransport,
		"EXIT_DNS_ONLY":           *flagDNSOnly,
	})
	addr := getenv("EXIT_ADDR", defaultAddr)
	upstream := getenv("EXIT_UPSTREAM_ADDR", "")

	ln, err := listenTransport(getenv("EXIT_TRANSPORT", "tcp"), addr)
	if err != nil {
		panic(err)
	}
	fmt.Println("Astra Exit listening on", ln.Addr().String())
	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		go handle(conn, upstream)
	}
}

func handle(conn net.Conn, upstream string) {
	defer conn.Close()
	if getenvBool("EXIT_TUN_ENABLE", false) {
		handleTun(conn)
		return
	}
	if getenvBool("EXIT_PROXY_MODE", false) {
		handleProxy(conn)
		return
	}
	if upstream == "" {
		echo(conn)
		return
	}
	allowed, reason, target := checkEgressPolicy(upstream)
	if !allowed {
		fmt.Println("egress denied:", reason)
		return
	}
	up, err := dialTransport(getenv("EXIT_UPSTREAM_TRANSPORT", "tcp"), target)
	if err != nil {
		return
	}
	defer up.Close()
	go io.Copy(up, conn)
	io.Copy(conn, up)
}

func handleProxy(conn net.Conn) {
	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		return
	}
	line = strings.TrimSpace(line)
	parts := strings.Split(line, " ")
	if len(parts) < 2 || strings.ToUpper(parts[0]) != "CONNECT" {
		_, _ = conn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
		return
	}
	target := parts[1]
	if !strings.Contains(target, ":") {
		target = target + ":80"
	}
	allowed, reason, target := checkEgressPolicy(target)
	if !allowed {
		_, _ = conn.Write([]byte("HTTP/1.1 403 Forbidden\r\n\r\n"))
		fmt.Println("proxy denied:", reason)
		return
	}
	up, err := dialTransport(getenv("EXIT_UPSTREAM_TRANSPORT", "tcp"), target)
	if err != nil {
		_, _ = conn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer up.Close()
	go io.Copy(up, reader)
	io.Copy(conn, up)
}

func handleTun(conn net.Conn) {
	tunName := getenv("ASTRA_TUN_NAME", "astra0")
	tunMTU := getenvInt("ASTRA_TUN_MTU", 1400)
	dev, err := tun.Create(tunName, tunMTU)
	if err != nil {
		fmt.Println("tun create failed:", err)
		return
	}
	defer tun.Close(dev)
	fmt.Printf("EXIT TUN up: %s (mtu=%d)\n", dev.Name, dev.MTU)

	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)

	go logTunStats()
	go func() {
		buf := make([]byte, 65535)
		for {
			n, err := tun.ReadPacket(dev, buf)
			if err != nil {
				log.Printf("tun read error: %v", err)
				return
			}
			if n <= 0 || n > 0xffff {
				continue
			}
			atomic.AddUint64(&tunTxBytes, uint64(n))
			_ = writePacket(writer, buf[:n])
		}
	}()

	for {
		payload, err := readPacket(reader)
		if err != nil {
			log.Printf("conn read error: %v", err)
			return
		}
		if len(payload) == 0 {
			continue
		}
		atomic.AddUint64(&tunRxBytes, uint64(len(payload)))
		_, _ = tun.WritePacket(dev, payload)
	}
}

var tunTxBytes uint64
var tunRxBytes uint64

func logTunStats() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		tx := atomic.LoadUint64(&tunTxBytes)
		rx := atomic.LoadUint64(&tunRxBytes)
		log.Printf("tun stats: tx=%d rx=%d", tx, rx)
	}
}

func echo(conn net.Conn) {
	reader := bufio.NewReader(conn)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		_, _ = conn.Write([]byte(line))
	}
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func getenvInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil {
			return parsed
		}
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
		alpn := getenv("EXIT_TLS_ALPN", "h2")
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
		return transport.TLSTransport{ServerName: getenv("EXIT_TLS_HOST", "astra.local"), ALPN: []string{"h2", "http/1.1"}, Profile: "chrome"}.Dial(context.Background(), addr)
	default:
		return transport.TCPTransport{}.Dial(context.Background(), addr)
	}
}

func checkEgressPolicy(upstream string) (bool, string, string) {
	host, port, err := net.SplitHostPort(upstream)
	if err != nil {
		return false, "invalid upstream", upstream
	}
	portNum := parsePort(port)
	if getenvBool("EXIT_DNS_ONLY", false) && portNum != 53 {
		return false, "dns only", upstream
	}
	if forced := getenv("EXIT_FORCE_DNS", ""); forced != "" && portNum == 53 {
		upstream = forced
		host, port, err = net.SplitHostPort(upstream)
		if err != nil {
			return false, "invalid forced dns", upstream
		}
		portNum = parsePort(port)
	}

	if isDeniedHost(host, getenvList("EXIT_DENY_HOSTS")) {
		return false, "host denied", upstream
	}
	if isDeniedPort(portNum, getenvList("EXIT_DENY_PORTS")) {
		return false, "port denied", upstream
	}
	if isDeniedCIDR(host, getenvList("EXIT_DENY_CIDRS")) {
		return false, "cidr denied", upstream
	}

	allowHosts := getenvList("EXIT_ALLOW_HOSTS")
	allowPorts := getenvList("EXIT_ALLOW_PORTS")
	allowCIDRs := getenvList("EXIT_ALLOW_CIDRS")
	if len(allowHosts) > 0 && !isAllowedHost(host, allowHosts) {
		return false, "host not allowed", upstream
	}
	if len(allowPorts) > 0 && !isAllowedPort(portNum, allowPorts) {
		return false, "port not allowed", upstream
	}
	if len(allowCIDRs) > 0 && !isAllowedCIDR(host, allowCIDRs) {
		return false, "cidr not allowed", upstream
	}
	return true, "", upstream
}

func getenvList(key string) []string {
	raw := getenv(key, "")
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func parsePort(p string) int {
	port, _ := strconv.Atoi(p)
	return port
}

func isDeniedHost(host string, patterns []string) bool {
	for _, p := range patterns {
		if matchHost(host, p) {
			return true
		}
	}
	return false
}

func isAllowedHost(host string, patterns []string) bool {
	for _, p := range patterns {
		if matchHost(host, p) {
			return true
		}
	}
	return false
}

func matchHost(host, pattern string) bool {
	if strings.HasPrefix(pattern, "*.") {
		return strings.HasSuffix(host, pattern[1:])
	}
	return strings.EqualFold(host, pattern)
}

func isDeniedPort(port int, list []string) bool {
	for _, p := range list {
		if parsePort(p) == port {
			return true
		}
	}
	return false
}

func isAllowedPort(port int, list []string) bool {
	for _, p := range list {
		if parsePort(p) == port {
			return true
		}
	}
	return false
}

func isDeniedCIDR(host string, list []string) bool {
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, cidr := range list {
		if _, block, err := net.ParseCIDR(cidr); err == nil && block.Contains(ip) {
			return true
		}
	}
	return false
}

func isAllowedCIDR(host string, list []string) bool {
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, cidr := range list {
		if _, block, err := net.ParseCIDR(cidr); err == nil && block.Contains(ip) {
			return true
		}
	}
	return false
}

func getenvBool(key string, def bool) bool {
	if v := os.Getenv(key); v != "" {
		return v == "1" || strings.ToLower(v) == "true"
	}
	return def
}

func writePacket(writer *bufio.Writer, payload []byte) error {
	if len(payload) > 0xffff {
		return nil
	}
	header := make([]byte, 2)
	binary.BigEndian.PutUint16(header, uint16(len(payload)))
	if _, err := writer.Write(header); err != nil {
		return err
	}
	if _, err := writer.Write(payload); err != nil {
		return err
	}
	return writer.Flush()
}

func readPacket(reader *bufio.Reader) ([]byte, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(reader, header); err != nil {
		return nil, err
	}
	length := int(binary.BigEndian.Uint16(header))
	if length <= 0 {
		return nil, nil
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(reader, payload); err != nil {
		return nil, err
	}
	return payload, nil
}
