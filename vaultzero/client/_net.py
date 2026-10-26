"""Transport policy shared by the SDK and embedding adapters."""

from __future__ import annotations

from urllib.parse import urlsplit

_LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1"}


def require_secure_url(url: str, label: str) -> None:
    """Allow HTTPS anywhere, plain HTTP only for loopback hosts.

    Parsing the URL matters: a prefix check such as ``startswith("http://localhost")`` also
    accepts ``http://localhost.attacker.example``.
    """
    parts = urlsplit(url)
    if parts.scheme == "https" and parts.hostname:
        return
    if parts.scheme == "http" and parts.hostname in _LOOPBACK_HOSTS:
        return
    raise ValueError(f"{label} must use HTTPS (plain HTTP is allowed only for loopback hosts)")
