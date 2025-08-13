package main

import (
	"bufio"
	"io"
	"log/slog"
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
	var logger *slog.Logger
	{
		var level slog.Level
		switch os.Getenv("SSHPROXY_LOG_LEVEL") {
		case "debug":
			level = slog.LevelDebug
		case "info":
			level = slog.LevelInfo
		case "warn":
			level = slog.LevelWarn
		case "error":
			level = slog.LevelError
		default:
			level = slog.LevelInfo
		}
		logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
	}
	if len(os.Args) != 3 {
		logger.Error("Usage error", "listen_addr", os.Args[1], "target_addr", os.Args[2])
		os.Exit(1)
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
				logger.Error("Failed to open log file", "error", err)
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
				logger.Debug("IP failure count", "ip", ip, "count", recent)
				if recent >= banThreshold {
					banList.Ban(ip, banDuration)
					logger.Info("Banned IP", "ip", ip, "duration", banDuration, "failures", recent)
				}
			}
			banList.Cleanup()
			time.Sleep(60 * time.Second)
		}
	}()

	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		logger.Error("Failed to listen on", "listen_addr", listenAddr, "error", err)
		os.Exit(1)
	}
	logger.Info("TCP SSH Proxy listening", "listen_addr", listenAddr, "target_addr", targetAddr)

	for {
		clientConn, err := ln.Accept()
		if err != nil {
			logger.Error("Failed to accept connection", "error", err)
			continue
		}
		remoteAddr, _, err := net.SplitHostPort(clientConn.RemoteAddr().String())
		if err != nil {
			logger.Error("Failed to parse remote address", "error", err)
			clientConn.Close()
			continue
		}
		if banList.IsBanned(remoteAddr) {
			logger.Warn("Rejected banned IP", "ip", remoteAddr)
			clientConn.Close()
			continue
		}
		go handleTCPProxy(clientConn, targetAddr, logger)
	}
}

func handleTCPProxy(clientConn net.Conn, targetAddr string, logger *slog.Logger) {
	defer clientConn.Close()

	targetConn, err := net.Dial("tcp", targetAddr)
	if err != nil {
		logger.Error("Failed to connect to target", "target", targetAddr, "error", err)
		return
	}
	defer targetConn.Close()

	// Bidirectional copy
	go io.Copy(targetConn, clientConn)
	io.Copy(clientConn, targetConn)
}
