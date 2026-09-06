FROM docker.io/library/debian:bookworm-slim@sha256:5ae3c39ebd15e229dcedd5cee596b2497182493d41ff162e824ba13fc1b2b867
RUN apt-get update && apt-get install -y --no-install-recommends openssh-server python3 sudo \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -m -u 10001 -s /bin/sh -p x analyst \
    && printf 'analyst:dac-test-password\n' | chpasswd \
    && printf 'analyst ALL=(root) ALL\n' > /etc/sudoers.d/dac-fixture \
    && chmod 0440 /etc/sudoers.d/dac-fixture \
    && mkdir -p /run/sshd /keys /samples \
    && printf 'Port 2222\nHostKey /keys/host_key\nAuthorizedKeysFile /keys/authorized_keys\nPasswordAuthentication yes\nKbdInteractiveAuthentication no\nUsePAM no\nPermitRootLogin no\nAllowUsers analyst\nAllowTcpForwarding no\nAllowAgentForwarding no\nSubsystem sftp internal-sftp\n' > /etc/ssh/sshd_config
EXPOSE 2222
ENTRYPOINT ["/usr/sbin/sshd", "-D", "-e"]
