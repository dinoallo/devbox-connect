#!/bin/bash

# Configuration
SSH_HOST="${SSH_HOST:-127.0.0.1}"
SSH_PORT="${SSH_PORT:-2222}"
SSH_USER="${SSH_USER:-test}"
SSH_KEY="${SSH_KEY:-clientkey}"
LOG_DIR="$(dirname "$0")"
LOG_NOT_BANNED="$LOG_DIR/auth_not_banned.log"
LOG_BANNED="$LOG_DIR/auth.log"

# Get local IP used for SSH connection
LOCAL_IP=$(ssh -i "$SSH_KEY" -p "$SSH_PORT" -o BatchMode=yes -o ConnectTimeout=5 "$SSH_USER@$SSH_HOST" 'echo $SSH_CONNECTION' 2>/dev/null | awk '{print $2}')
if [ -z "$LOCAL_IP" ]; then
  echo "Failed to get local IP from SSH connection" >&2
  exit 1
fi

now() { date '+%b %d %H:%M:%S'; }

# Generate auth_not_banned.log
cat > "$LOG_NOT_BANNED" <<EOF
$(now) localhost sshd[12345]: Accepted publickey for test from $LOCAL_IP port 54321 ssh2: RSA SHA256:examplekey
$(now) localhost sshd[12345]: pam_unix(sshd:session): session opened for user test by (uid=0)
$(now) localhost sshd[12345]: pam_unix(sshd:session): session closed for user test
$(now) localhost sshd[12345]: Failed password for root from $LOCAL_IP port 54322 ssh2
$(now) localhost sshd[12345]: Connection closed by authenticating user test $LOCAL_IP port 54321 [preauth]
$(now) localhost sshd[12345]: error: maximum authentication attempts exceeded for test from $LOCAL_IP port 54323 ssh2 [preauth]
EOF

# Generate auth.log (with 5 extra failures to trigger ban)
cat > "$LOG_BANNED" <<EOF
$(now) localhost sshd[12345]: Accepted publickey for test from $LOCAL_IP port 54321 ssh2: RSA SHA256:examplekey
$(now) localhost sshd[12345]: pam_unix(sshd:session): session opened for user test by (uid=0)
$(now) localhost sshd[12345]: pam_unix(sshd:session): session closed for user test
$(now) localhost sshd[12345]: Failed password for root from $LOCAL_IP port 54322 ssh2
$(now) localhost sshd[12345]: Connection closed by authenticating user test $LOCAL_IP port 54321 [preauth]
$(now) localhost sshd[12345]: error: maximum authentication attempts exceeded for test from $LOCAL_IP port 54323 ssh2 [preauth]
EOF

for i in {0..4}; do
  ts=$(date -d "+$((i+1)) min" '+%b %d %H:%M:%S')
  echo "$ts localhost sshd[$((12346+i))]: Failed password for root from $LOCAL_IP port $((54324+i)) ssh2" >> "$LOG_BANNED"
done

echo "Generated $LOG_NOT_BANNED and $LOG_BANNED with local IP $LOCAL_IP"
