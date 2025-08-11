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
	"golang.org/x/crypto/ssh/agent"
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

	// Load authorized public keys
	authKeysBytes, err := os.ReadFile("../test/authorized_keys")
	if err != nil {
		log.Fatalf("Failed to load authorized_keys: %v", err)
	}
	authorizedKeysMap := map[string]ssh.PublicKey{}
	for len(authKeysBytes) > 0 {
		pubKey, _, _, rest, err := ssh.ParseAuthorizedKey(authKeysBytes)
		if err != nil {
			break
		}
		authorizedKeysMap[string(pubKey.Marshal())] = pubKey
		authKeysBytes = rest
	}

	config := &ssh.ServerConfig{
		PublicKeyCallback: func(c ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
			ip := c.RemoteAddr().String()
			if v, ok := backoff.Load(ip); ok {
				until := v.(time.Time)
				if time.Now().Before(until) {
					log.Printf("Backoff active for %s, rejecting authentication", ip)
					return nil, errors.New("unauthorized")
				}
			}
			if _, ok := authorizedKeysMap[string(pubKey.Marshal())]; ok {
				return &ssh.Permissions{
					Extensions: map[string]string{"userpubkey": string(pubKey.Marshal())},
				}, nil
			}
			backoff.Store(ip, time.Now().Add(backoffDuration))
			log.Printf("Failed public key authentication for %s, backoff until %v", ip, time.Now().Add(backoffDuration))
			return nil, errors.New("unauthorized")
		},
	}
	privateBytes, err := os.ReadFile("../test/serverkey")
	if err != nil {
		log.Fatalf("Failed to load private key (serverkey): %v", err)
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

	// ...no longer needed: userPubKey extraction...

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

		// Connect to target SSH server using agent forwarding
		var targetClient *ssh.Client
		if sshConn != nil {
			// Try to connect to the user's SSH agent
			agentSock := os.Getenv("SSH_AUTH_SOCK")
			if agentSock == "" {
				log.Printf("SSH_AUTH_SOCK not set, cannot use agent forwarding.")
				channel.Close()
				continue
			}
			agentConn, err := net.Dial("unix", agentSock)
			if err != nil {
				log.Printf("Failed to connect to SSH agent: %v", err)
				channel.Close()
				continue
			}
			ag := agent.NewClient(agentConn)
			targetConfig := &ssh.ClientConfig{
				User:            sshConn.User(),
				Auth:            []ssh.AuthMethod{ssh.PublicKeysCallback(ag.Signers)},
				HostKeyCallback: ssh.InsecureIgnoreHostKey(),
				Timeout:         10 * time.Second,
			}
			targetClient, err = ssh.Dial("tcp", targetAddr, targetConfig)
			if err != nil {
				log.Printf("Failed to connect to target %s with agent forwarding: %v", targetAddr, err)
				channel.Close()
				continue
			}
		} else {
			log.Printf("No SSH connection available for agent forwarding.")
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
