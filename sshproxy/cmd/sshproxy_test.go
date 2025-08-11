package main

import (
	"os"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestTCPProxy_RealSSHClient(t *testing.T) {
	// Start proxy in goroutine
	go func() {
		os.Args = []string{"sshproxy", ":2223", "localhost:2222"}
		main()
	}()
	time.Sleep(1 * time.Second)

	// Load private key from test/clientkey
	key, err := os.ReadFile("../test/clientkey")
	if err != nil {
		t.Fatalf("Failed to read client key: %v", err)
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
	client, err := ssh.Dial("tcp", "localhost:2223", config)
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
