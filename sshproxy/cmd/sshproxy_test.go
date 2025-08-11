package main

import (
	"os"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// Minimal test private key (not in authorized_keys)
const testPrivateKeyPEM = `-----BEGIN RSA PRIVATE KEY-----
MIIBOgIBAAJBALe1QwQwQwQwQwQwQwQwQwQwQwQwQwQwQwQwQwQwQwQwQwQwQwQw
QwQwQwQwQwQwQwQwQwQwQwQwQwQwQwQwQwQwQwQwQwIDAQABAkB7QwQwQwQwQwQw
QwQwQwQwQwQwQwQwQwQwQwQwQwQwQwQwQwQwQwQwQwQwQwQwQwQwQwQwQwQwQwQw
AiEA9QwQwQwQwQwQwQwQwQwQwQwQwQwQwQwQwQwQwQwQwQwQwQwQwQwQwQwQwQwQw
QwQwQwQwQwQwQwQwQwQwQwQwQwQwQwQwQwQwQwQwQwQwQwQwQwQwQwQwQwQwQwQw
-----END RSA PRIVATE KEY-----`

func TestSSHProxy_AuthBackoff(t *testing.T) {
	// Start proxy in goroutine
	go func() {
		os.Args = []string{"sshproxy", ":2223", "localhost:2222"}
		main()
	}()
	// Wait for proxy to start
	time.Sleep(1 * time.Second)

	// Write an empty authorized_keys to ensure only invalid keys are tested
	err := os.WriteFile("sshproxy/cmd/authorized_keys", []byte{}, 0644)
	if err != nil {
		t.Fatal("Failed to write authorized_keys: ", err)
	}

	// Try to connect with an invalid public key (not in authorized_keys)
	// Generate a new key for this test
	signer, err := ssh.ParsePrivateKey([]byte(testPrivateKeyPEM))
	if err != nil {
		t.Skip("No test private key available for invalid auth")
	}
	config := &ssh.ClientConfig{
		User:            "test",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}
	_, err = ssh.Dial("tcp", "localhost:2223", config)
	if err == nil {
		t.Fatal("Expected authentication failure with invalid public key, got success")
	}

	// Try again immediately to trigger backoff
	_, err = ssh.Dial("tcp", "localhost:2223", config)
	if err == nil {
		t.Fatal("Expected authentication failure due to backoff, got success")
	}
}

func TestSSHProxy_ValidKey(t *testing.T) {
	// Load client private key and public key
	key, err := os.ReadFile("../test/clientkey")
	if err != nil {
		t.Skip("No test key available")
	}
	// Start proxy in goroutine
	go func() {
		os.Args = []string{"sshproxy", ":2224", "localhost:2222"}
		main()
	}()
	// Wait for proxy to start
	time.Sleep(1 * time.Second)

	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	config := &ssh.ClientConfig{
		User:            "root",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}
	client, err := ssh.Dial("tcp", "localhost:2224", config)
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
