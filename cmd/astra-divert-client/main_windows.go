//go:build windows

package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"astra/internal/client/identity"
	"astra/internal/config"
	"astra/internal/learning"
	"astra/internal/obfs"
	"astra/internal/protocol"
	"astra/internal/sni"
	"astra/internal/transport"
	"golang.org/x/net/http2/hpack"
)

const (
	defaultEntryAddr = "127.0.0.1:8443"
	identityFile     = "identity.dat"
	tokenFile        = "token.dat"
	learningFile     = "learning.json"
)

func main() {
	configPath := flag.String("config", getenv("ASTRA_CONFIG", "configs/astra-divert-client.json"), "config path")
	flag.Parse()
	if err := config.ApplyEnvFile(*configPath); err != nil {
		log.Fatalf("config load failed: %v", err)
	}

	entryAddr := getenv("ENTRY_ADDR", defaultEntryAddr)
	entryIP, entryPort := resolveEntry(entryAddr)
	if entryIP != "" && entryPort > 0 {
		entryAddr = net.JoinHostPort(entryIP, strconv.Itoa(entryPort))
	}
	filter := getenv("ASTRA_DIVERT_FILTER", "")
	if filter == "" {
		filter = buildFilter(entryIP, entryPort)
	}

	conn, err := connectToEntry(entryAddr)
	if err != nil {
		log.Fatalf("failed to connect to entry: %v", err)
	}
	defer conn.Close()

	stream := transport.WrapConn(conn, transport.FrameConfig{
		MinPad: getenvInt("ASTRA_FRAME_MIN_PAD", 0),
		MaxPad: getenvInt("ASTRA_FRAME_MAX_PAD", 0),
	})
	reader := bufio.NewReader(stream)
	writer := bufio.NewWriter(stream)
	writerMu := &sync.Mutex{}

	log.Printf("WinDivert filter: %s", filter)
	var flags uint64
	// If injection is being rejected by the TCP/IP stack, debug mode makes
	// WinDivertSend block until the packet exits the stack and return an error.
	if getenv("ASTRA_DIVERT_DEBUG", "") != "" {
		flags |= 0x4 // WINDIVERT_FLAG_DEBUG
	}
	handle, err := openDivert(filter, flags)
	if err != nil {
		log.Fatalf("windivert open failed: %v", err)
	}
	defer handle.Close()
	if maj, min := handle.GetVersion(); maj != 0 || min != 0 {
		log.Printf("WinDivert driver version %d.%d", maj, min)
	}
	log.Printf("Divert running. Entry=%s, filter=%q", entryAddr, filter)

	entryIP4 := net.ParseIP(entryIP).To4()
	virtualIP4 := net.ParseIP(getenv("ASTRA_VIRTUAL_IP", "10.10.0.2")).To4()
	local := &ipState{}
	injectIfIdx = uint32(getenvInt("ASTRA_DIVERT_IFIDX", 0))
	injectSubIfIdx = uint32(getenvInt("ASTRA_DIVERT_SUBIFIDX", 0))
	closeOnce := &sync.Once{}
	closeHandle := func() {
		closeOnce.Do(func() {
			_ = handle.Close()
		})
	}

	go keepAlive(writer, writerMu, closeHandle)
	go pumpTunnelToDivert(reader, handle, virtualIP4, local, closeHandle)
	pumpDivertToTunnel(writer, writerMu, handle, entryIP4, entryPort, virtualIP4, local, closeHandle)
}

var divertTxBytes uint64
var divertRxBytes uint64
var bypassLogged uint32
var lastOutboundIfMu sync.Mutex
var lastOutboundIf divertAddress
var injectIfIdx uint32
var injectSubIfIdx uint32
var injectIfLogged uint32

type ipState struct {
	mu   sync.Mutex
	real net.IP // detected local IPv4 (e.g. 192.168.x.x)
}

func (s *ipState) setIfEmpty(ip net.IP) {
	if ip == nil {
		return
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.real == nil {
		s.real = append(net.IP(nil), ip4...)
	}
}

func (s *ipState) get() net.IP {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.real == nil {
		return nil
	}
	return append(net.IP(nil), s.real...)
}

func pumpDivertToTunnel(writer *bufio.Writer, writerMu *sync.Mutex, handle divertHandle, entryIP4 net.IP, entryPort int, virtualIP4 net.IP, local *ipState, closeHandle func()) {
	buf := make([]byte, 65535)
	for {
		n, addr, err := handle.Recv(buf)
		if err != nil {
			log.Printf("divert recv error: %v", err)
			closeHandle()
			return
		}
		if n <= 0 || n > len(buf) {
			log.Printf("divert recv invalid length: %d", n)
			continue
		}
		if !addr.Outbound() {
			calcDivertChecksums(buf[:n], nil)
			if _, err := handle.Send(buf[:n], addr); err != nil {
				log.Printf("divert inbound reinject error: %v", err)
				closeHandle()
				return
			}
			continue
		}
		// Outbound packet below.
		packet := append([]byte(nil), buf[:n]...)
		if shouldBypass(packet, entryIP4, entryPort) {
			if atomic.CompareAndSwapUint32(&bypassLogged, 0, 1) {
				log.Printf("bypassing entry traffic on port %d", entryPort)
			}
			calcDivertChecksums(packet, nil)
			if _, err := handle.Send(packet, addr); err != nil {
				log.Printf("divert bypass send error: %v", err)
				return
			}
			continue
		}

		// Remember the full address from Recv so we can reuse it for inbound inject
		// (driver may validate that Send address came from a prior Recv).
		lastOutboundIfMu.Lock()
		lastOutboundIf = addr
		lastOutboundIfMu.Unlock()

		// Divert sees real LAN source IPs (e.g. 192.168.x.x). If we forward those
		// unchanged, the exit will not route replies back into the tunnel.
		// Translate src -> virtual IP (10.10.0.2 by default).
		if virtualIP4 != nil && local != nil {
			if src, ok := ipv4Src(packet); ok {
				local.setIfEmpty(src)
				real := local.get()
				if real != nil && src.Equal(real) && len(packet) >= 20 {
					copy(packet[12:16], virtualIP4)
				}
			}
		}

		// Packets captured before NIC offload may carry incomplete checksums.
		// Recalculate after any rewrite and before tunneling.
		calcDivertChecksums(packet, nil)
		atomic.AddUint64(&divertTxBytes, uint64(n))
		writerMu.Lock()
		err = writePacket(writer, packet)
		writerMu.Unlock()
		if err != nil {
			log.Printf("tunnel write error: %v", err)
			closeHandle()
			return
		}
	}
}

func pumpTunnelToDivert(reader *bufio.Reader, handle divertHandle, virtualIP4 net.IP, local *ipState, closeHandle func()) {
	for {
		payload, err := readPacket(reader)
		if err != nil {
			log.Printf("tunnel read error: %v", err)
			closeHandle()
			return
		}
		if len(payload) == 0 {
			continue
		}
		// Translate dst virtual IP -> real local LAN IP before reinjecting (unless disabled for debugging).
		noDstRewrite := getenv("ASTRA_DIVERT_NO_DST_REWRITE", "") != ""
		if !noDstRewrite && virtualIP4 != nil && local != nil {
			real := local.get()
			if real != nil && len(payload) >= 20 {
				dst := net.IPv4(payload[16], payload[17], payload[18], payload[19])
				if dst.Equal(virtualIP4) {
					copy(payload[16:20], real.To4())
				}
			}
		}
		atomic.AddUint64(&divertRxBytes, uint64(len(payload)))
		calcDivertChecksums(payload, nil)

		// Prefer address from last outbound Recv (driver may only accept Send with Recv-derived address).
		lastOutboundIfMu.Lock()
		var inj divertAddress
		var fromRecv bool
		if lastOutboundIf.IfIdx != 0 {
			inj = lastOutboundIf.ToInbound()
			fromRecv = true
		} else if injectIfIdx != 0 {
			inj = NewInboundAddress(injectIfIdx, injectSubIfIdx)
		} else {
			inj = NewInboundAddress(0, 0)
		}
		lastOutboundIfMu.Unlock()
		calcDivertChecksums(payload, &inj)
		if atomic.CompareAndSwapUint32(&injectIfLogged, 0, 1) {
			log.Printf("inject inbound: IfIdx=%d SubIfIdx=%d (from_recv=%v no_dst_rewrite=%v)", inj.IfIdx, inj.SubIfIdx, fromRecv, noDstRewrite)
		}

		trySend := func(a *divertAddress) (int, error) {
			n, errEx := handle.SendEx(payload, a)
			if errEx == nil {
				return n, nil
			}
			codeEx := errnoCode(errEx)
			n, err := handle.Send(payload, *a)
			if err == nil {
				return n, nil
			}
			code := errnoCode(err)
			log.Printf("divert send: SendEx failed code=%d (%v); Send failed code=%d (%v)",
				codeEx, errEx, code, err)
			return n, err
		}
		n, err := trySend(&inj)
		if err != nil && inj.IfIdx != 0 {
			inj.IfIdx, inj.SubIfIdx = 0, 0
			calcDivertChecksums(payload, &inj)
			n, err = trySend(&inj)
			if err == nil && atomic.CompareAndSwapUint32(&injectIfLogged, 1, 2) {
				log.Printf("inject succeeded with IfIdx=0")
			}
		}
		if err != nil {
			log.Printf("divert send error: %v (packet_len=%d dst=%s)",
				err, len(payload), formatIPDst(payload))
			if errnoCode(err) == 87 {
				log.Printf("divert: code 87 = WinDivert 2.2 likely does not allow injecting inbound packets that were not captured by Recv; for full tunnel on Windows consider WFP or TUN (see ASTRA_ROADMAP.md)")
			}
			return
		}
		if n != len(payload) {
			log.Printf("divert send short write: %d/%d", n, len(payload))
		}
	}
}

func ipv4Src(packet []byte) (net.IP, bool) {
	if len(packet) < 20 {
		return nil, false
	}
	if (packet[0]>>4)&0x0f != 4 {
		return nil, false
	}
	ihl := int(packet[0]&0x0f) * 4
	if ihl < 20 || len(packet) < ihl {
		return nil, false
	}
	return net.IPv4(packet[12], packet[13], packet[14], packet[15]), true
}

func errnoCode(err error) int {
	if err == nil {
		return 0
	}
	if e, ok := err.(syscall.Errno); ok {
		return int(e)
	}
	return 0
}

func formatIPDst(packet []byte) string {
	if len(packet) < 20 {
		return "?"
	}
	if (packet[0]>>4)&0x0f != 4 {
		return "?"
	}
	ihl := int(packet[0]&0x0f) * 4
	if ihl < 20 || len(packet) < ihl+4 {
		return "?"
	}
	dst := net.IPv4(packet[16], packet[17], packet[18], packet[19])
	if packet[9] == 6 && len(packet) >= ihl+4 {
		port := binary.BigEndian.Uint16(packet[ihl+2 : ihl+4])
		return fmt.Sprintf("%s:%d", dst, port)
	}
	return dst.String()
}

func keepAlive(writer *bufio.Writer, writerMu *sync.Mutex, closeHandle func()) {
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()
	empty := []byte{}
	for range ticker.C {
		writerMu.Lock()
		err := writePacket(writer, empty)
		writerMu.Unlock()
		if err != nil {
			log.Printf("keepalive write error: %v", err)
			closeHandle()
			return
		}
	}
}

func buildFilter(entryIP string, entryPort int) string {
	base := "outbound and ip and tcp"
	if entryPort <= 0 {
		return base
	}
	// Exclude entry connection by port only.
	return fmt.Sprintf("%s and tcp.DstPort != %d", base, entryPort)
}

func shouldBypass(packet []byte, entryIP4 net.IP, entryPort int) bool {
	if entryIP4 == nil || entryPort <= 0 {
		return false
	}
	if len(packet) < 20 {
		return false
	}
	ihl := int(packet[0]&0x0f) * 4
	if ihl < 20 || len(packet) < ihl+4 {
		return false
	}
	if packet[9] != 6 {
		return false
	}
	dst := net.IPv4(packet[16], packet[17], packet[18], packet[19])
	src := net.IPv4(packet[12], packet[13], packet[14], packet[15])
	srcPort := int(binary.BigEndian.Uint16(packet[ihl : ihl+2]))
	dstPort := int(binary.BigEndian.Uint16(packet[ihl+2 : ihl+4]))
	if dst.Equal(entryIP4) && dstPort == entryPort {
		return true
	}
	return src.Equal(entryIP4) && srcPort == entryPort
}

func resolveEntry(addr string) (string, int) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return "", 0
	}
	port, _ := strconv.Atoi(portStr)
	if ip := net.ParseIP(host); ip != nil {
		return ip.String(), port
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return "", port
	}
	for _, ip := range ips {
		if ip.To4() != nil {
			return ip.String(), port
		}
	}
	return "", port
}

func connectToEntry(entryAddr string) (net.Conn, error) {
	id, err := loadIdentity(identityFile)
	if err != nil {
		return nil, err
	}
	token := loadToken(tokenFile)
	networkID := getenv("ASTRA_NETWORK_ID", "")
	if networkID == "" {
		networkID = detectNetworkID()
	}

	learn := learning.Load(learningFile)
	profiles := defaultProfiles()
	obfsCfg := obfs.Config{
		Mode:             obfs.ModePreamble,
		MaxPreamble:      getenvInt("OBFS_PREAMBLE_MAX", 64),
		PreambleTemplate: getenv("OBFS_PREAMBLE_TEMPLATE", "random"),
	}
	transports := parseTransports(getenv("ASTRA_TRANSPORTS", "tcp"))

	var conn net.Conn
	for _, transportName := range transports {
		profileOrder := rankProfilesForTransport(learn, profiles, transportName, networkID)
		for _, profile := range profileOrder {
			resp, c, _, err := attemptHandshake(entryAddr, transportName, profile, id, token, obfsCfg, networkID)
			key := learningKey(profile.ID, transportName, networkID)
			learn.Update(key, 0, err == nil && resp != nil && resp.Status == protocol.StatusOK)
			if err != nil {
				continue
			}
			if resp.Token != "" {
				_ = os.WriteFile(tokenFile, []byte(resp.Token), 0600)
			}
			if resp.Status != protocol.StatusOK {
				log.Printf("handshake denied: status=%s code=%s message=%s", resp.Status, resp.Code, resp.Message)
				c.Close()
				continue
			}
			conn = c
			break
		}
		if conn != nil {
			break
		}
	}
	if conn == nil {
		return nil, fmt.Errorf("failed to connect to entry")
	}
	return conn, nil
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

func loadIdentity(path string) (*identity.Identity, error) {
	if _, err := os.Stat(path); err == nil {
		return identity.LoadIdentity(path)
	}
	id, err := identity.GenerateIdentity()
	if err != nil {
		return nil, err
	}
	if err := id.Save(path); err != nil {
		return nil, err
	}
	return id, nil
}

func generateNonce() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func loadToken(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(bytes.TrimSpace(b))
}

func defaultProfiles() []sni.Profile {
	return []sni.Profile{
		{ID: "google-h2", ServerName: "google.com", ALPN: "h2", FingerprintID: "chrome"},
		{ID: "google-h1", ServerName: "google.com", ALPN: "http/1.1", FingerprintID: "chrome"},
		{ID: "gstatic-h2", ServerName: "gstatic.com", ALPN: "h2", FingerprintID: "chrome"},
		{ID: "youtube-h2", ServerName: "youtube.com", ALPN: "h2", FingerprintID: "chrome"},
		{ID: "android-h2", ServerName: "android.com", ALPN: "h2", FingerprintID: "android"},
		{ID: "play-h2", ServerName: "play.googleapis.com", ALPN: "h2", FingerprintID: "android"},
		{ID: "google-ff", ServerName: "google.com", ALPN: "h2", FingerprintID: "firefox"},
	}
}

func rankProfilesForTransport(store *learning.Store, profiles []sni.Profile, transportName string, networkID string) []sni.Profile {
	if store == nil {
		return profiles
	}
	ordered := make([]sni.Profile, 0, len(profiles))
	for _, p := range profiles {
		ordered = append(ordered, p)
	}
	sort.SliceStable(ordered, func(i, j int) bool {
		return store.Score(learningKey(ordered[i].ID, transportName, networkID)) > store.Score(learningKey(ordered[j].ID, transportName, networkID))
	})
	return ordered
}

func attemptHandshake(addr string, transportName string, profile sni.Profile, id *identity.Identity, token string, obfsCfg obfs.Config, networkID string) (*protocol.HandshakeResponse, net.Conn, time.Duration, error) {
	start := time.Now()
	conn, err := dialTransport(transportName, addr, profile)
	if err != nil {
		return nil, nil, 0, err
	}
	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)

	timestamp := time.Now().Unix()
	nonce := generateNonce()
	obfsMode := string(obfsCfg.Mode)
	if transportName == "tls" {
		obfsMode = string(obfs.ModeNone)
	}
	req := &protocol.HandshakeRequest{
		Version:   protocol.Version,
		ClientID:  id.ClientID,
		PublicKey: hex.EncodeToString(id.PublicKey),
		Timestamp: timestamp,
		Nonce:     nonce,
		Token:     token,
		NetworkID: networkID,
		ProfileID: profile.ID,
		Transport: transportName,
		ObfsMode:  obfsMode,
	}
	signature := id.Sign([]byte(protocol.SignPayload(req)))
	req.Signature = hex.EncodeToString(signature)

	preamble := []byte(nil)
	if obfsCfg.Enabled() && transportName != "tls" {
		preamble = obfs.GeneratePreamble(obfsCfg.MaxPreamble, obfsCfg.PreambleTemplate)
	}
	if transportName == "tls" {
		if err := writeTLSAppPreamble(writer, getenv("TLS_APP_PREAMBLE_TEMPLATE", "http2frames")); err != nil {
			conn.Close()
			return nil, nil, time.Since(start), err
		}
	}
	if maxFrag := getenvInt("TLS_FRAGMENT_MAX", 0); transportName == "tls" && maxFrag > 0 {
		if err := writeHandshakeFragmented(writer, req, preamble, maxFrag); err != nil {
			conn.Close()
			return nil, nil, time.Since(start), err
		}
	} else {
		if err := protocol.WriteHandshake(writer, req, preamble); err != nil {
			conn.Close()
			return nil, nil, time.Since(start), err
		}
	}
	resp, err := protocol.ReadResponse(reader)
	if err != nil {
		conn.Close()
		return nil, nil, time.Since(start), err
	}
	return resp, conn, time.Since(start), nil
}

func parseTransports(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return []string{"tcp"}
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return []string{"tcp"}
	}
	return out
}

func dialTransport(name, addr string, profile sni.Profile) (net.Conn, error) {
	switch name {
	case "rudp":
		return transport.ReliableUDPTransport{}.Dial(context.Background(), addr)
	case "udp":
		return transport.UDPTransport{}.Dial(context.Background(), addr)
	case "tls":
		alpn := profile.ALPN
		if alpn == "" {
			alpn = "h2"
		}
		return transport.TLSTransport{
			ServerName: profile.ServerName,
			ALPN:       []string{alpn, "http/1.1"},
			Profile:    profile.FingerprintID,
			Timeout:    4 * time.Second,
		}.Dial(context.Background(), addr)
	default:
		return transport.TCPTransport{Timeout: 4 * time.Second}.Dial(context.Background(), addr)
	}
}

func learningKey(profileID, transportName, networkID string) string {
	if networkID == "" {
		networkID = "default"
	}
	return transportName + "|" + profileID + "|" + networkID
}

func writeTLSAppPreamble(writer *bufio.Writer, template string) error {
	switch template {
	case "http1":
		_, _ = writer.WriteString(buildHTTP1Preamble(getenvInt("TLS_HTTP1_PAD_BYTES", 0)))
	case "http2":
		_, _ = writer.WriteString("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
	case "http2frames":
		_, _ = writer.WriteString("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
		writeHTTP2Settings(writer)
		writeHTTP2Headers(writer, "example.com")
		writeHTTP2Data(writer, []byte("ping"))
		writeHTTP2Ping(writer)
	default:
		return nil
	}
	return writer.Flush()
}

func writeHTTP2Settings(writer *bufio.Writer) {
	payload := []byte{0x00, 0x03, 0x00, 0x00, 0x00, 0x64}
	writeHTTP2Frame(writer, 0x4, 0x0, 0, payload)
}

func writeHTTP2Ping(writer *bufio.Writer) {
	payload := []byte("12345678")
	writeHTTP2Frame(writer, 0x6, 0x0, 0, payload)
}

func writeHTTP2Frame(writer *bufio.Writer, frameType byte, flags byte, streamID uint32, payload []byte) {
	length := len(payload)
	header := []byte{
		byte(length >> 16), byte(length >> 8), byte(length),
		frameType,
		flags,
		byte(streamID >> 24), byte(streamID >> 16), byte(streamID >> 8), byte(streamID),
	}
	_, _ = writer.Write(header)
	_, _ = writer.Write(payload)
}

func writeHTTP2Headers(writer *bufio.Writer, authority string) {
	var buf bytes.Buffer
	enc := hpack.NewEncoder(&buf)
	_ = enc.WriteField(hpack.HeaderField{Name: ":method", Value: "CONNECT"})
	_ = enc.WriteField(hpack.HeaderField{Name: ":authority", Value: authority})
	_ = enc.WriteField(hpack.HeaderField{Name: ":scheme", Value: "https"})
	_ = enc.WriteField(hpack.HeaderField{Name: "user-agent", Value: "Mozilla/5.0"})
	_ = enc.WriteField(hpack.HeaderField{Name: "accept", Value: "*/*"})
	writeHTTP2Frame(writer, 0x1, 0x4, 1, buf.Bytes())
}

func writeHTTP2Data(writer *bufio.Writer, data []byte) {
	writeHTTP2Frame(writer, 0x0, 0x1, 1, data)
}

func buildHTTP1Preamble(pad int) string {
	base := "GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\n"
	if pad > 0 {
		random := make([]byte, pad)
		_, _ = rand.Read(random)
		base += "X-Pad: " + hex.EncodeToString(random) + "\r\n"
	}
	return base + "\r\n"
}

func writeHandshakeFragmented(writer *bufio.Writer, req *protocol.HandshakeRequest, preamble []byte, maxChunk int) error {
	if len(preamble) > 0 {
		if _, err := writer.Write(preamble); err != nil {
			return err
		}
	}
	data, err := json.Marshal(req)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	for len(data) > 0 {
		chunk := maxChunk
		if chunk <= 0 || chunk > len(data) {
			chunk = len(data)
		}
		if _, err := writer.Write(data[:chunk]); err != nil {
			return err
		}
		data = data[chunk:]
	}
	return writer.Flush()
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

func detectNetworkID() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "unknown"
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		name := strings.ToLower(iface.Name)
		switch {
		case strings.Contains(name, "wi-fi") || strings.Contains(name, "wifi") || strings.Contains(name, "wlan") || strings.Contains(name, "wireless"):
			return "wifi:" + iface.Name
		case strings.Contains(name, "wwan") || strings.Contains(name, "cell") || strings.Contains(name, "lte") || strings.Contains(name, "4g") || strings.Contains(name, "5g"):
			return "cell:" + iface.Name
		case strings.Contains(name, "eth"):
			return "eth:" + iface.Name
		}
	}
	return "unknown"
}
