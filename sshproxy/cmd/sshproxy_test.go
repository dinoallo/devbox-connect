package main

import (
	"os"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestSSHProxy_AuthBackoff(t *testing.T) {
	// Start proxy in goroutine
	go func() {
		os.Args = []string{"sshproxy", ":2222", "localhost:22"}
		main()
	}()
	// Wait for proxy to start
	time.Sleep(1 * time.Second)

	// Try to connect with invalid password
	config := &ssh.ClientConfig{
		User:            "test",
		Auth:            []ssh.AuthMethod{ssh.Password("wrong")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}
	_, err := ssh.Dial("tcp", "localhost:2222", config)
	if err == nil {
		t.Fatal("Expected authentication failure, got success")
	}
}

func TestSSHProxy_ValidKey(t *testing.T) {
	// Load test private key
	key, err := os.ReadFile("sshproxy/cmd/id_rsa")
	if err != nil {
		t.Skip("No test key available")
	}
	// Start proxy in goroutine
	go func() {
		os.Args = []string{"sshproxy", ":2223", "localhost:22"}
		main()
	}()
	// Wait for proxy to start
	time.Sleep(1 * time.Second)

	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	config := &ssh.ClientConfig{
		User:            "test",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}
	client, err := ssh.Dial("tcp", "localhost:2223", config)
	if err != nil {
		t.Fatalf("Failed to connect with valid key: %v", err)
	}
	defer client.Close()

	// Open a session and run a command
	sess, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	out, err := sess.Output("echo hello")
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != "hello\n" {
		t.Fatalf("Unexpected output: %s", out)
	}
}
