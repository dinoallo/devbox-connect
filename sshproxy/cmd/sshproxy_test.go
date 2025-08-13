package main

import (
	"os"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// Helper to start the proxy for tests
func startProxy(t *testing.T, listenAddr, targetAddr, logPath string) {
	os.Setenv("SSHPROXY_AUTH_LOG", logPath)
	go func() {
		t.Log("start sshproxy")
		os.Args = []string{"sshproxy", listenAddr, targetAddr}
		main()
	}()
	time.Sleep(1 * time.Second)
}

func TestSSHProxy_Forwarding(t *testing.T) {
	// Start proxy (no banning)
	banLog := "../test/auth.log"
	startProxy(t, ":2245", "localhost:2222", banLog)

	// Load private key from test/clientkey
	clientKey := "../test/clientkey"
	key, err := os.ReadFile(clientKey)
	if err != nil {
		t.Skip("No test key available for SSH client test")
	}
	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		t.Fatalf("Failed to parse client key: %v", err)
	}

	config := &ssh.ClientConfig{
		User:            "root",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}

	// Connect to SSH server via proxy
	client, err := ssh.Dial("tcp", "localhost:2245", config)
	if err != nil {
		t.Fatalf("Failed to connect to SSH server via proxy: %v", err)
	}
	defer client.Close()

	// Open a session and run a command
	session, err := client.NewSession()
	if err != nil {
		t.Fatalf("Failed to open SSH session: %v", err)
	}
	defer session.Close()

	output, err := session.Output("echo hello")
	if err != nil {
		t.Fatalf("Failed to run command: %v", err)
	}
	if string(output) != "hello\n" {
		t.Fatalf("Unexpected output: %q", output)
	}
	t.Logf("SSH command output: %q", output)
}

func TestSSHProxy_Banning(t *testing.T) {
	// Use a log file with repeated failures from 127.0.0.1
	banLog := "../test/auth.log"
	startProxy(t, ":2246", "localhost:2222", banLog)

	// Wait for ban goroutine to process log
	time.Sleep(2 * time.Second)

	// Try to load private key from test/clientkey and connect from banned IP using a real SSH client
	clientKey := "../test/clientkey"
	key, err := os.ReadFile(clientKey)
	if err != nil {
		t.Skip("No test key available for SSH client test")
	}
	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		t.Fatalf("Failed to parse client key: %v", err)
	}

	config := &ssh.ClientConfig{
		User:            "root",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}

	_, err = ssh.Dial("tcp", "localhost:2246", config)
	if err == nil {
		t.Fatalf("Expected connection to be rejected for banned IP, but SSH client connected successfully")
	} else {
		t.Logf("Connection rejected as expected for banned IP: %v", err)
	}
}
