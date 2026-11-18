"""sshd_config per profile (OpenSSH 9.x on Alpine).

vulnerable  root login, password auth (root:toor, lab:lab), legacy SHA-1 KEX / CBC / hmac-sha1 / ssh-rsa
baseline    OpenSSH defaults, no root, publickey only
hardened    BSI TR-02102-4 algorithm set (NIST ECDH/DH-16/18, AES-GCM/CTR, SHA-2 ETM MACs, ECDSA host key),
            publickey only for 'lab', no forwarding, tight auth limits
"""
from __future__ import annotations

from .profiles import Profile

KEY_DIR = "/run/sshd-keys"
CONF = "/etc/seclab/sshd_config"
AUTH_KEYS_SRC = "/etc/seclab/authorized_keys"

BSI_KEX = ("ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,"
           "diffie-hellman-group18-sha512,diffie-hellman-group16-sha512")
BSI_CIPHERS = "aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr"
BSI_MACS = ("hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,"
            "hmac-sha2-512,hmac-sha2-256")
SSH_CAPS = ("AUDIT_WRITE", "CHOWN", "FOWNER", "KILL", "NET_BIND_SERVICE", "SETGID", "SETUID", "SYS_CHROOT")


def render(p: Profile) -> str:
    common = ["Port 22", "AddressFamily inet", "LogLevel VERBOSE", "Subsystem sftp internal-sftp",
              "PermitEmptyPasswords no", "UseDNS no"]
    if p.name == "vulnerable":
        body = [
            "HostKey /etc/ssh/ssh_host_rsa_key",
            "HostKey /etc/ssh/ssh_host_ed25519_key",
            "PidFile /run/sshd.pid",
            "PermitRootLogin yes",
            "PasswordAuthentication yes",
            "KbdInteractiveAuthentication no",
            "MaxAuthTries 10",
            "LoginGraceTime 120",
            "AllowTcpForwarding yes",
            "AllowAgentForwarding yes",
            "GatewayPorts yes",
            "KexAlgorithms +diffie-hellman-group14-sha1",
            "Ciphers +aes128-cbc,aes256-cbc",
            "MACs +hmac-sha1",
            "HostKeyAlgorithms +ssh-rsa",
            "PubkeyAcceptedAlgorithms +ssh-rsa",
        ]
    else:
        body = [
            f"HostKey {KEY_DIR}/ssh_host_ecdsa_key",
            f"PidFile {KEY_DIR}/sshd.pid",
            f"AuthorizedKeysFile {KEY_DIR}/authorized_keys",
            "PermitRootLogin no",
            "PasswordAuthentication no",
            "KbdInteractiveAuthentication no",
            "PubkeyAuthentication yes",
            "AuthenticationMethods publickey",
            "AllowUsers lab",
            "X11Forwarding no",
            "PermitUserEnvironment no",
            "PermitTunnel no",
            "GatewayPorts no",
        ]
        if p.name == "hardened":
            body += [
                "MaxAuthTries 3",
                "MaxSessions 2",
                "MaxStartups 5:50:10",
                "LoginGraceTime 20",
                "ClientAliveInterval 300",
                "ClientAliveCountMax 2",
                "AllowTcpForwarding no",
                "AllowAgentForwarding no",
                "AllowStreamLocalForwarding no",
                f"KexAlgorithms {BSI_KEX}",
                f"Ciphers {BSI_CIPHERS}",
                f"MACs {BSI_MACS}",
                "HostKeyAlgorithms ecdsa-sha2-nistp384,ecdsa-sha2-nistp256",
                "PubkeyAcceptedAlgorithms ecdsa-sha2-nistp384,ecdsa-sha2-nistp256,rsa-sha2-512,rsa-sha2-256",
            ]
        else:
            body += ["MaxAuthTries 4", "LoginGraceTime 60"]
    return "\n".join(common + body) + "\n"


def start_script(p: Profile) -> str:
    sshd = f"exec /usr/sbin/sshd -D -e -f {CONF}"
    if p.name == "vulnerable":
        return f"ssh-keygen -A >/dev/null && printf 'root:toor\\nlab:lab\\n' | chpasswd && {sshd}"
    return (
        f"ssh-keygen -q -t ecdsa -b 384 -N '' -f {KEY_DIR}/ssh_host_ecdsa_key"
        f" && cp {AUTH_KEYS_SRC} {KEY_DIR}/authorized_keys && chmod 644 {KEY_DIR}/authorized_keys"
        f" && {sshd}"
    )
