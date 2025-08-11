package main

import (
	"bufio"
	"io"
	"log"
	"net"
	"os"
	"regexp"
	"sync"
	"time"
)

// BanList stores banned IPs and their expiry
type BanList struct {
	sync.RWMutex
	bans map[string]time.Time
}

func (b *BanList) IsBanned(ip string) bool {
	b.RLock()
	defer b.RUnlock()
	until, ok := b.bans[ip]
	return ok && time.Now().Before(until)
}

func (b *BanList) Ban(ip string, duration time.Duration) {
	b.Lock()
	b.bans[ip] = time.Now().Add(duration)
	b.Unlock()
}

func (b *BanList) Cleanup() {
	b.Lock()
	now := time.Now()
	for ip, until := range b.bans {
		if now.After(until) {
			delete(b.bans, ip)
		}
	}
	b.Unlock()
}

func main() {
	if len(os.Args) != 3 {
		log.Fatalf("Usage: %s <listen_addr> <target_addr>", os.Args[0])
	}
	listenAddr := os.Args[1]
	targetAddr := os.Args[2]

	logFile := os.Getenv("SSHPROXY_AUTH_LOG")
	if logFile == "" {
		logFile = "/var/log/auth.log"
	}
	banThreshold := 5
	banWindow := 10 * time.Minute
	banDuration := 10 * time.Minute

	banList := &BanList{bans: make(map[string]time.Time)}

	// Start log parser goroutine
	go func() {
		failedRegex := regexp.MustCompile(`(?i)Failed password for .* from ([0-9.]+) port`)
		for {
			ipFails := make(map[string][]time.Time)
			f, err := os.Open(logFile)
			if err != nil {
				log.Printf("Failed to open log file: %v", err)
				time.Sleep(30 * time.Second)
				continue
			}
			scanner := bufio.NewScanner(f)
			now := time.Now()
			for scanner.Scan() {
				line := scanner.Text()
				matches := failedRegex.FindStringSubmatch(line)
				if len(matches) == 2 {
					ip := matches[1]
					ipFails[ip] = append(ipFails[ip], now)
				}
			}
			f.Close()
			for ip, times := range ipFails {
				// Only count failures in the last banWindow
				recent := 0
				for _, t := range times {
					if now.Sub(t) <= banWindow {
						recent++
					}
				}
				if recent >= banThreshold {
					banList.Ban(ip, banDuration)
					log.Printf("Banned IP %s for %v due to %d failures", ip, banDuration, recent)
				}
			}
			banList.Cleanup()
			time.Sleep(60 * time.Second)
		}
	}()

	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Fatalf("Failed to listen on %s: %v", listenAddr, err)
	}
	log.Printf("TCP SSH Proxy listening on %s, forwarding to %s", listenAddr, targetAddr)

	for {
		clientConn, err := ln.Accept()
		if err != nil {
			log.Printf("Failed to accept connection: %v", err)
			continue
		}
		remoteAddr, _, err := net.SplitHostPort(clientConn.RemoteAddr().String())
		if err != nil {
			log.Printf("Failed to parse remote address: %v", err)
			clientConn.Close()
			continue
		}
		if banList.IsBanned(remoteAddr) {
			log.Printf("Rejected banned IP: %s", remoteAddr)
			clientConn.Close()
			continue
		}
		go handleTCPProxy(clientConn, targetAddr)
	}
}

func handleTCPProxy(clientConn net.Conn, targetAddr string) {
	defer clientConn.Close()

	targetConn, err := net.Dial("tcp", targetAddr)
	if err != nil {
		log.Printf("Failed to connect to target %s: %v", targetAddr, err)
		return
	}
	defer targetConn.Close()

	// Bidirectional copy
	go io.Copy(targetConn, clientConn)
	io.Copy(clientConn, targetConn)
}
