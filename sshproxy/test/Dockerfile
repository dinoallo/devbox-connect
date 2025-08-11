FROM alpine:latest

RUN apk add --no-cache openssh

RUN mkdir -p /var/run/sshd

COPY ./clientkey.pub /root/.ssh/authorized_keys
RUN chmod 600 /root/.ssh/authorized_keys && chown root:root /root/.ssh/authorized_keys

# Generate host keys if not present, then start sshd
CMD ["/bin/sh", "-c", "ssh-keygen -A && /usr/sbin/sshd -D"]
