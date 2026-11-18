"""Security profiles: one source of truth for TLS, HTTP and container hardening.

vulnerable  - deliberately weak target for audit practice (still resource-capped, bound to 127.0.0.1)
baseline    - Mozilla "intermediate" TLS, core OWASP headers, CIS-style container hardening
hardened    - TLS per BSI TR-02102-2 (ECDHE + AES-GCM, NIST curves), strict OWASP headers,
              method allow-list, rate limit, full container lockdown
"""
from __future__ import annotations

from dataclasses import dataclass

Headers = tuple[tuple[str, str], ...]


@dataclass(frozen=True)
class TLSPolicy:
    protocols: tuple[str, ...]
    ciphers: str
    prefer_server_ciphers: bool
    ecdh_curve: str | None
    session_tickets: bool


@dataclass(frozen=True)
class HTTPPolicy:
    server_tokens: bool
    autoindex: bool
    redirect_to_https: bool
    allowed_methods: tuple[str, ...] | None
    client_max_body_size: str
    rate_limit_rps: int | None
    tight_timeouts: bool
    deny_dotfiles: bool
    headers: Headers


@dataclass(frozen=True)
class ContainerPolicy:
    read_only: bool
    drop_all_caps: bool
    no_new_privileges: bool
    user: str | None  # None -> image default (root)
    # Resource ceilings are lab safety, applied to every profile.
    memory: str = "64m"
    cpus: str = "0.25"
    pids: int = 64


@dataclass(frozen=True)
class Profile:
    name: str
    description: str
    tls: TLSPolicy
    http: HTTPPolicy
    container: ContainerPolicy


MOZILLA_INTERMEDIATE = (
    "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
    "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:"
    "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:"
    "DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-CHACHA20-POLY1305"
)
BSI_TR02102_ECDSA = "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256"

NGINX_UID = "101:101"  # 'nginx' user in the official alpine image

PROFILES: dict[str, Profile] = {
    "vulnerable": Profile(
        name="vulnerable",
        description="Legacy TLS 1.0+, weak ciphers, version disclosure, autoindex, no headers, root container",
        tls=TLSPolicy(
            protocols=("TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"),
            ciphers="ALL:@SECLEVEL=0",
            prefer_server_ciphers=False,
            ecdh_curve=None,
            session_tickets=True,
        ),
        http=HTTPPolicy(
            server_tokens=True,
            autoindex=True,
            redirect_to_https=False,
            allowed_methods=None,
            client_max_body_size="100m",
            rate_limit_rps=None,
            tight_timeouts=False,
            deny_dotfiles=False,
            headers=(),
        ),
        container=ContainerPolicy(read_only=False, drop_all_caps=False, no_new_privileges=False, user=None),
    ),
    "baseline": Profile(
        name="baseline",
        description="Mozilla intermediate TLS 1.2/1.3, core OWASP headers, non-root read-only container",
        tls=TLSPolicy(
            protocols=("TLSv1.2", "TLSv1.3"),
            ciphers=MOZILLA_INTERMEDIATE,
            prefer_server_ciphers=False,
            ecdh_curve=None,
            session_tickets=False,
        ),
        http=HTTPPolicy(
            server_tokens=False,
            autoindex=False,
            redirect_to_https=True,
            allowed_methods=None,
            client_max_body_size="1m",
            rate_limit_rps=None,
            tight_timeouts=True,
            deny_dotfiles=True,
            headers=(
                ("Strict-Transport-Security", "max-age=31536000"),
                ("X-Content-Type-Options", "nosniff"),
                ("X-Frame-Options", "SAMEORIGIN"),
                ("Referrer-Policy", "strict-origin-when-cross-origin"),
                ("Content-Security-Policy", "default-src 'self'; frame-ancestors 'self'"),
            ),
        ),
        container=ContainerPolicy(read_only=True, drop_all_caps=True, no_new_privileges=True, user=NGINX_UID),
    ),
    "hardened": Profile(
        name="hardened",
        description="BSI TR-02102-2 TLS, strict OWASP headers, GET/HEAD only, rate limit, full lockdown",
        tls=TLSPolicy(
            protocols=("TLSv1.2", "TLSv1.3"),
            ciphers=BSI_TR02102_ECDSA,
            prefer_server_ciphers=True,
            ecdh_curve="secp384r1:prime256v1",
            session_tickets=False,
        ),
        http=HTTPPolicy(
            server_tokens=False,
            autoindex=False,
            redirect_to_https=True,
            allowed_methods=("GET", "HEAD"),
            client_max_body_size="1k",
            rate_limit_rps=10,
            tight_timeouts=True,
            deny_dotfiles=True,
            headers=(
                ("Strict-Transport-Security", "max-age=63072000; includeSubDomains"),
                ("X-Content-Type-Options", "nosniff"),
                ("X-Frame-Options", "DENY"),
                ("Referrer-Policy", "no-referrer"),
                (
                    "Content-Security-Policy",
                    "default-src 'none'; img-src 'self'; style-src 'self'; "
                    "frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
                ),
                ("Permissions-Policy", "geolocation=(), camera=(), microphone=(), payment=()"),
                ("Cross-Origin-Opener-Policy", "same-origin"),
                ("Cross-Origin-Resource-Policy", "same-origin"),
            ),
        ),
        container=ContainerPolicy(read_only=True, drop_all_caps=True, no_new_privileges=True, user=NGINX_UID),
    ),
}


def get_profile(name: str) -> Profile:
    try:
        return PROFILES[name]
    except KeyError:
        raise ValueError(f"unknown profile '{name}', choose from: {', '.join(PROFILES)}") from None
