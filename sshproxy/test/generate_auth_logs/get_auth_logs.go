package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/ssh"
)

func main() {
	sshHost := getenv("SSH_HOST", "127.0.0.1")
	sshPort := getenv("SSH_PORT", "2222")
	sshUser := getenv("SSH_USER", "test")
	sshKey := getenv("SSH_KEY", "../test/clientkey")

	logDir := filepath.Dir(os.Args[0])
	logNotBanned := filepath.Join(logDir, "auth_not_banned.log")
	logBanned := filepath.Join(logDir, "auth.log")

	localIP, err := getLocalIP(sshHost, sshPort, sshUser, sshKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to get local IP: %v\n", err)
		os.Exit(1)
	}

	if err := writeAuthNotBanned(logNotBanned, localIP); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to write auth_not_banned.log: %v\n", err)
		os.Exit(1)
	}
	if err := writeAuthBanned(logBanned, localIP); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to write auth.log: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Generated %s and %s with local IP %s\n", logNotBanned, logBanned, localIP)
}

func getenv(key, def string) string {
	val := os.Getenv(key)
	if val == "" {
		return def
	}
	return val
}

func getLocalIP(host, port, user, keyPath string) (string, error) {
	key, err := os.ReadFile(keyPath)
	if err != nil {
		return "", fmt.Errorf("read key: %w", err)
	}
	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		return "", fmt.Errorf("parse key: %w", err)
	}
	config := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}
	client, err := ssh.Dial("tcp", host+":"+port, config)
	if err != nil {
		return "", fmt.Errorf("ssh dial: %w", err)
	}
	defer client.Close()
	addr, ok := client.Conn.LocalAddr().(*net.TCPAddr)
	if !ok {
		return "", fmt.Errorf("local address is not TCPAddr")
	}
	return addr.IP.String(), nil
}

func now() string {
	return time.Now().Format("Jan 02 15:04:05")
}

func writeAuthNotBanned(path, ip string) error {
	lines := []string{
		fmt.Sprintf("%s localhost sshd[12345]: Accepted publickey for test from %s port 54321 ssh2: RSA SHA256:examplekey", now(), ip),
		fmt.Sprintf("%s localhost sshd[12345]: pam_unix(sshd:session): session opened for user test by (uid=0)", now()),
		fmt.Sprintf("%s localhost sshd[12345]: pam_unix(sshd:session): session closed for user test", now()),
		fmt.Sprintf("%s localhost sshd[12345]: Failed password for root from %s port 54322 ssh2", now(), ip),
		fmt.Sprintf("%s localhost sshd[12345]: Connection closed by authenticating user test %s port 54321 [preauth]", now(), ip),
		fmt.Sprintf("%s localhost sshd[12345]: error: maximum authentication attempts exceeded for test from %s port 54323 ssh2 [preauth]", now(), ip),
	}
	return os.WriteFile(path, []byte(joinLines(lines)), 0644)
}

func writeAuthBanned(path, ip string) error {
	lines := []string{
		fmt.Sprintf("%s localhost sshd[12345]: Accepted publickey for test from %s port 54321 ssh2: RSA SHA256:examplekey", now(), ip),
		fmt.Sprintf("%s localhost sshd[12345]: pam_unix(sshd:session): session opened for user test by (uid=0)", now()),
		fmt.Sprintf("%s localhost sshd[12345]: pam_unix(sshd:session): session closed for user test", now()),
		fmt.Sprintf("%s localhost sshd[12345]: Failed password for root from %s port 54322 ssh2", now(), ip),
		fmt.Sprintf("%s localhost sshd[12345]: Connection closed by authenticating user test %s port 54321 [preauth]", now(), ip),
		fmt.Sprintf("%s localhost sshd[12345]: error: maximum authentication attempts exceeded for test from %s port 54323 ssh2 [preauth]", now(), ip),
	}
	for i := 0; i < 5; i++ {
		t := time.Now().Add(time.Duration(i+1) * time.Minute)
		lines = append(lines, fmt.Sprintf("%s localhost sshd[%d]: Failed password for root from %s port %d ssh2",
			t.Format("Jan 02 15:04:05"), 12346+i, ip, 54324+i))
	}
	return os.WriteFile(path, []byte(joinLines(lines)), 0644)
}

func joinLines(lines []string) string {
	return fmt.Sprintf("%s\n", string([]byte(fmt.Sprintf("%s", lines))))
}
