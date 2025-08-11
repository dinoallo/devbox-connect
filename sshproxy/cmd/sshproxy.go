package main

import (
	"errors"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

func main() {
	if len(os.Args) != 3 {
		log.Fatalf("Usage: %s <listen_addr> <target_addr>", os.Args[0])
	}
	listenAddr := os.Args[1]
	targetAddr := os.Args[2]

	// Backoff map and mutex
	var backoff sync.Map
	backoffDuration := 30 * time.Second
	// authTimeout := 10 * time.Second // removed unused variable

	// SSH server config with password authentication
	config := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			ip := c.RemoteAddr().String()
			if v, ok := backoff.Load(ip); ok {
				until := v.(time.Time)
				if time.Now().Before(until) {
					log.Printf("Backoff active for %s, rejecting authentication", ip)
					return nil, errors.New("unauthorized")
				}
			}
			// Try to parse the password as a PEM private key
			_, err := ssh.ParsePrivateKey(pass)
			if err == nil {
				// Valid private key, allow login
				return &ssh.Permissions{
					Extensions: map[string]string{"userkey": string(pass)},
				}, nil
			}
			// Failed auth: set backoff
			backoff.Store(ip, time.Now().Add(backoffDuration))
			log.Printf("Failed authentication for %s, backoff until %v", ip, time.Now().Add(backoffDuration))
			return nil, errors.New("unauthorized")
		},
	}
	privateBytes, err := os.ReadFile("sshproxy/cmd/id_rsa")
	if err != nil {
		log.Fatalf("Failed to load private key (sshproxy/cmd/id_rsa): %v", err)
	}
	private, err := ssh.ParsePrivateKey(privateBytes)
	if err != nil {
		log.Fatalf("Failed to parse private key: %v", err)
	}
	config.AddHostKey(private)

	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Fatalf("Failed to listen on %s: %v", listenAddr, err)
	}
	log.Printf("SSH Proxy listening on %s, forwarding to %s", listenAddr, targetAddr)

	for {
		clientConn, err := ln.Accept()
		if err != nil {
			log.Printf("Failed to accept connection: %v", err)
			continue
		}
		go handleSSHConnection(clientConn, targetAddr, config)
	}
}

func handleSSHConnection(clientConn net.Conn, targetAddr string, config *ssh.ServerConfig) {
	defer clientConn.Close()

	// Set deadline for authentication
	clientConn.SetDeadline(time.Now().Add(10 * time.Second))
	sshConn, chans, reqs, err := ssh.NewServerConn(clientConn, config)
	if err != nil {
		log.Printf("SSH handshake failed: %v", err)
		return
	}
	// Remove deadline after handshake
	clientConn.SetDeadline(time.Time{})
	log.Printf("New SSH connection from %s (%s)", sshConn.RemoteAddr(), sshConn.ClientVersion())

	// Extract user's private key from permissions
	var userKey ssh.Signer
	if sshConn.Permissions != nil {
		if keyStr, ok := sshConn.Permissions.Extensions["userkey"]; ok {
			k, err := ssh.ParsePrivateKey([]byte(keyStr))
			if err == nil {
				userKey = k
			}
		}
	}

	// Log global requests
	go func() {
		for req := range reqs {
			log.Printf("Global request: %s", req.Type)
			req.Reply(false, nil)
		}
	}()

	// Forward each channel to the target
	for newChannel := range chans {
		if newChannel.ChannelType() != "session" {
			newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}
		channel, requests, err := newChannel.Accept()
		if err != nil {
			log.Printf("Could not accept channel: %v", err)
			continue
		}

		// Connect to target SSH server using user's key
		var targetClient *ssh.Client
		if userKey != nil {
			targetConfig := &ssh.ClientConfig{
				User:            sshConn.User(),
				Auth:            []ssh.AuthMethod{ssh.PublicKeys(userKey)},
				HostKeyCallback: ssh.InsecureIgnoreHostKey(),
				Timeout:         10 * time.Second,
			}
			targetClient, err = ssh.Dial("tcp", targetAddr, targetConfig)
			if err != nil {
				log.Printf("Failed to connect to target %s with user key: %v", targetAddr, err)
				channel.Close()
				continue
			}
		} else {
			log.Printf("No user key provided, cannot connect to upstream SSH server.")
			channel.Close()
			continue
		}

		// Open a session/channel to upstream
		upstreamChan, upstreamReqs, err := targetClient.OpenChannel("session", nil)
		if err != nil {
			log.Printf("Failed to open upstream session: %v", err)
			channel.Close()
			targetClient.Close()
			continue
		}

		// Wire up bidirectional copy
		go io.Copy(upstreamChan, channel)
		go io.Copy(channel, upstreamChan)

		// Optionally handle upstream requests (discard for now)
		go func() {
			for range upstreamReqs {
				// ignore
			}
		}()

		// Log channel requests
		go func(in <-chan *ssh.Request) {
			for req := range in {
				log.Printf("Channel request: %s", req.Type)
				req.Reply(false, nil)
			}
		}(requests)
	}
}
