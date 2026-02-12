package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"astra/internal/config"
)

func main() {
	configPath := flag.String("config", getenv("ASTRA_CONFIG", "configs/astra-lab.json"), "config path")
	flagMode := flag.String("mode", "", "LAB_MODE")
	flagListen := flag.String("listen", "", "LAB_LISTEN_ADDR")
	flagTarget := flag.String("target", "", "LAB_TARGET_ADDR")
	flagDrop := flag.String("drop", "", "LAB_DROP_PCT")
	flagDelay := flag.String("delay", "", "LAB_DELAY_MS")
	flagReset := flag.String("reset", "", "LAB_RESET_AFTER_BYTES")
	flag.Parse()
	_ = config.ApplyEnvFile(*configPath)
	config.ApplyOverrides(map[string]string{
		"LAB_MODE":              *flagMode,
		"LAB_LISTEN_ADDR":       *flagListen,
		"LAB_TARGET_ADDR":       *flagTarget,
		"LAB_DROP_PCT":          *flagDrop,
		"LAB_DELAY_MS":          *flagDelay,
		"LAB_RESET_AFTER_BYTES": *flagReset,
	})
	mode := getenv("LAB_MODE", "proxy")
	switch mode {
	case "load":
		runLoad()
	default:
		runProxy()
	}
}

func runProxy() {
	listenAddr := getenv("LAB_LISTEN_ADDR", "127.0.0.1:18080")
	targetAddr := getenv("LAB_TARGET_ADDR", "")
	if targetAddr == "" {
		panic("LAB_TARGET_ADDR required")
	}
	dropPct := getenvInt("LAB_DROP_PCT", 0)
	resetAfter := getenvInt("LAB_RESET_AFTER_BYTES", 0)
	delayMs := getenvInt("LAB_DELAY_MS", 0)

	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		panic(err)
	}
	fmt.Println("astra-lab proxy listening on", listenAddr, "->", targetAddr)
	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		go func(c net.Conn) {
			defer c.Close()
			if dropPct > 0 && rand.Intn(100) < dropPct {
				return
			}
			up, err := net.Dial("tcp", targetAddr)
			if err != nil {
				return
			}
			defer up.Close()
			if resetAfter > 0 {
				go copyWithReset(up, c, resetAfter, time.Duration(delayMs)*time.Millisecond)
				copyWithReset(c, up, resetAfter, time.Duration(delayMs)*time.Millisecond)
				return
			}
			go copyWithDelay(up, c, time.Duration(delayMs)*time.Millisecond)
			copyWithDelay(c, up, time.Duration(delayMs)*time.Millisecond)
		}(conn)
	}
}

func copyWithDelay(dst io.Writer, src io.Reader, delay time.Duration) {
	if delay <= 0 {
		_, _ = io.Copy(dst, src)
		return
	}
	buf := make([]byte, 4*1024)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			_, _ = dst.Write(buf[:n])
			time.Sleep(delay)
		}
		if err != nil {
			return
		}
	}
}

func copyWithReset(dst io.Writer, src io.Reader, limit int, delay time.Duration) {
	if limit <= 0 {
		copyWithDelay(dst, src, delay)
		return
	}
	buf := make([]byte, 4*1024)
	total := 0
	for {
		n, err := src.Read(buf)
		if n > 0 {
			total += n
			if total >= limit {
				return
			}
			_, _ = dst.Write(buf[:n])
			if delay > 0 {
				time.Sleep(delay)
			}
		}
		if err != nil {
			return
		}
	}
}

func runLoad() {
	target := getenv("LAB_TARGET_ADDR", "")
	if target == "" {
		panic("LAB_TARGET_ADDR required")
	}
	clients := getenvInt("LAB_CLIENTS", 20)
	requests := getenvInt("LAB_REQUESTS", 50)
	payloadSize := getenvInt("LAB_PAYLOAD_BYTES", 256)
	sleepMs := getenvInt("LAB_SLEEP_MS", 10)

	var wg sync.WaitGroup
	var mu sync.Mutex
	success := 0
	fail := 0

	fmt.Println("astra-lab load:", clients, "clients to", target)
	for i := 0; i < clients; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < requests; j++ {
				conn, err := net.Dial("tcp", target)
				if err != nil {
					mu.Lock()
					fail++
					mu.Unlock()
					continue
				}
				writer := bufio.NewWriter(conn)
				payload := strings.Repeat("A", payloadSize)
				_, _ = writer.WriteString(payload)
				_ = writer.Flush()
				_ = conn.Close()
				mu.Lock()
				success++
				mu.Unlock()
				if sleepMs > 0 {
					time.Sleep(time.Duration(sleepMs) * time.Millisecond)
				}
			}
		}()
	}
	wg.Wait()
	fmt.Printf("load finished: success=%d fail=%d\n", success, fail)
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
