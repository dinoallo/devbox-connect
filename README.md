## Devbox Connect

Devbox Connect is a collection of tools for secure connectivity and tunneling in Sealos Devbox.

### Components

1. `sshproxy` – A simple TCP SSH proxy that watches an auth log and temporarily bans brute‑force IPs based on failed password attempts.
2. `tunnel/ws` – WebSocket tunnel client/server (wst) for forwarding TCP traffic over WebSockets (e.g. to traverse restrictive networks).

### Why

Provide easily auditable, minimal tooling for:
- Local SSH hardening (basic dynamic banning without dependency on iptables)
- Lightweight TCP tunneling over WebSockets

### Quick Start

Clone (Go 1.22+ recommended):
```bash
git clone https://github.com/dinoallo/devbox-connect
cd devbox-connect
go work sync  # optional: ensure module deps tidy
```

#### Run sshproxy
```bash
cd sshproxy/cmd
go run . :2244 localhost:2222
```
Environment:
- `SSHPROXY_LOG_LEVEL` = debug|info|warn|error (default info)
- `SSHPROXY_AUTH_LOG` = path to auth log (default /var/log/auth.log)

Default ban policy (in‑memory): 5 failures within 10m -> 10m ban.

Generate sample auth logs for tests:
```bash
cd sshproxy/test/generate_auth_logs
go run get_auth_logs.go
```

#### Run WebSocket Tunnel
See `tunnel/ws/README.md` for details. Minimal example:
```bash
# Server
cd tunnel/ws/server
go run .

# Client
cd tunnel/ws/client
go run . -insecure -target ws://127.0.0.1:8081/ws
```

### Repository Structure
```
go.work
sshproxy/                 # SSH proxy + banning logic
	cmd/                    # Main binary
	test/                   # Test assets (auth log generators, keys, Dockerfile)
tunnel/
	ws/                     # WebSocket tunnel implementation
		client/
		server/
```

### Development

Formatting / linting (basic):
```bash
go fmt ./...
go vet ./...
```

Run all tests:
```bash
go test ./...
```

Each component has its own `go.mod`; the `go.work` file ties them together for local development.

### Security Notes
- Bans are in‑memory only (reset on restart).
- Log parsing re-reads the entire file periodically (no incremental seek yet).
- WebSocket tunnel client `-insecure` flag skips TLS verification—avoid in production.

### Roadmap Ideas
- Configurable ban thresholds via flags / env
- Incremental log tailing
- Persistent / shared ban store
- mTLS for WebSocket tunnel

### Contributing
Small focused PRs welcome. Please run `go test ./...` before submitting.

### License
See `LICENSE` file.

### Acknowledgements
Built for internal development workflows; shared in case it helps others.

