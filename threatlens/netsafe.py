"""SSRF-safe networking.

A scanner that fetches attacker-supplied URLs is itself a juicy SSRF primitive,
so every connection goes through these helpers:

* the destination is resolved once and *every* address must be public;
* the socket is then opened to the validated IP (no second DNS lookup, so DNS
  rebinding cannot swap in an internal address);
* redirects are followed manually and each hop is validated again;
* only http/https on a short list of ports, with size and time caps.
"""
from __future__ import annotations

import ipaddress
import socket
import time
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

import requests
import urllib3
from requests.adapters import HTTPAdapter
from urllib3.connection import HTTPConnection, HTTPSConnection
from urllib3.connectionpool import HTTPConnectionPool, HTTPSConnectionPool
from urllib3.util import connection as u3conn

from . import config

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

USER_AGENT = "ThreatLens/1.0 (security scanner; read-only)"


class BlockedTarget(Exception):
    """The destination is not allowed to be contacted."""


# --------------------------------------------------------------------------- IP policy
def _embedded_v4(ip):
    if ip.version != 6:
        return None
    if ip.ipv4_mapped:
        return ip.ipv4_mapped
    if ip.sixtofour:
        return ip.sixtofour
    if ip.teredo:
        return ip.teredo[1]
    if ip.packed[:12] == bytes.fromhex("0064ff9b0000000000000000"):  # NAT64
        return ipaddress.IPv4Address(ip.packed[12:])
    return None


def ip_is_public(ip) -> bool:
    emb = _embedded_v4(ip)
    if emb is not None:
        return ip_is_public(emb)
    return bool(ip.is_global and not ip.is_multicast)


def resolve_public(host: str, port: int) -> list[tuple[int, str]]:
    """Resolve *host* and return (family, ip) pairs, refusing non-public targets."""
    host = host.strip("[]")
    try:
        literal = ipaddress.ip_address(host)
        infos = [(socket.AF_INET6 if literal.version == 6 else socket.AF_INET, str(literal))]
    except ValueError:
        try:
            raw = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        except socket.gaierror as exc:
            raise OSError(f"DNS lookup failed for {host}: {exc}") from exc
        seen, infos = set(), []
        for fam, _t, _p, _c, sockaddr in raw:
            if sockaddr[0] not in seen:
                seen.add(sockaddr[0])
                infos.append((fam, sockaddr[0]))
    if not infos:
        raise OSError(f"No addresses found for {host}")
    if not config.allow_private():
        for _fam, ip in infos:
            if not ip_is_public(ipaddress.ip_address(ip.split("%")[0])):
                raise BlockedTarget(f"{host} resolves to a non-public address ({ip})")
    return infos


def validate_url(url: str) -> tuple[str, str, int]:
    if len(url) > 2048:
        raise ValueError("URL is longer than 2048 characters")
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise ValueError("Only http and https URLs can be scanned")
    if not parts.hostname:
        raise ValueError("URL has no host")
    try:
        port = parts.port
    except ValueError as exc:
        raise ValueError("URL has an invalid port") from exc
    port = port or (443 if parts.scheme == "https" else 80)
    if not (config.any_port() or config.allow_private()) and port not in config.ALLOWED_PORTS:
        raise BlockedTarget(f"Port {port} is not on the scanner's allowed list")
    return parts.scheme, parts.hostname, port


# --------------------------------------------------------------------------- pinned connections
def pinned_connect(host, port, timeout, source_address=None, socket_options=None):
    last: Exception | None = None
    for _fam, ip in resolve_public(host, port):
        try:
            return u3conn.create_connection(
                (ip, port), timeout, source_address=source_address, socket_options=socket_options
            )
        except OSError as exc:
            last = exc
    raise last or OSError("connection failed")


class _SafeHTTPConnection(HTTPConnection):
    def _new_conn(self):
        return pinned_connect(
            getattr(self, "_dns_host", self.host), self.port, self.timeout,
            self.source_address, self.socket_options,
        )


class _SafeHTTPSConnection(HTTPSConnection):
    def _new_conn(self):
        return pinned_connect(
            getattr(self, "_dns_host", self.host), self.port, self.timeout,
            self.source_address, self.socket_options,
        )


class _SafeHTTPPool(HTTPConnectionPool):
    ConnectionCls = _SafeHTTPConnection


class _SafeHTTPSPool(HTTPSConnectionPool):
    ConnectionCls = _SafeHTTPSConnection


class _SafeAdapter(HTTPAdapter):
    def init_poolmanager(self, *args, **kwargs):
        super().init_poolmanager(*args, **kwargs)
        self.poolmanager.pool_classes_by_scheme = {"http": _SafeHTTPPool, "https": _SafeHTTPSPool}


def _session() -> requests.Session:
    s = requests.Session()
    s.trust_env = False  # never inherit proxies/credentials from the environment
    adapter = _SafeAdapter(max_retries=0)
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    s.headers.update({
        "User-Agent": USER_AGENT,
        "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.5",
    })
    return s


# --------------------------------------------------------------------------- fetch
@dataclass
class FetchResult:
    url: str
    final_url: str = ""
    status: int | None = None
    headers: dict = field(default_factory=dict)
    set_cookies: list = field(default_factory=list)
    content_type: str = ""
    body: str = ""
    truncated: bool = False
    redirects: list = field(default_factory=list)
    error: str | None = None
    elapsed_ms: int = 0


_REDIRECT_CODES = (301, 302, 303, 307, 308)


def safe_fetch(url: str, method: str = "GET", read_body: bool = True) -> FetchResult:
    started = time.time()
    res = FetchResult(url=url, final_url=url)
    timeout = config.fetch_timeout()
    session = _session()
    r = None
    current = url
    try:
        for _hop in range(config.max_redirects() + 1):
            _scheme, host, port = validate_url(current)
            resolve_public(host, port)  # early, readable error; pinned_connect re-checks
            # verify=False on purpose: certificate trust is judged by the certificate
            # engine, and suspicious sites often have broken certificates.
            r = session.request(
                method, current, allow_redirects=False, stream=True,
                timeout=timeout, verify=False,
            )
            res.status = r.status_code
            res.final_url = current
            location = r.headers.get("Location")
            if r.status_code in _REDIRECT_CODES and location:
                nxt = urljoin(current, location)
                res.redirects.append({"from": current, "to": nxt, "status": r.status_code})
                r.close()
                current = nxt
                continue
            res.headers = {k.lower(): v for k, v in r.headers.items()}
            try:
                res.set_cookies = list(r.raw.headers.getlist("Set-Cookie"))
            except Exception:  # pragma: no cover - defensive
                res.set_cookies = []
            res.content_type = res.headers.get("content-type", "")
            ctype = res.content_type.lower()
            if read_body and (not ctype or any(t in ctype for t in ("html", "text", "xml", "json"))):
                buf = bytearray()
                limit = config.max_body_bytes()
                for chunk in r.iter_content(16384):
                    buf.extend(chunk[:max(0, limit - len(buf))])
                    if len(buf) >= limit:
                        res.truncated = True
                        break
                    if time.time() - started > timeout * 3:
                        res.truncated = True
                        break
                try:
                    res.body = bytes(buf).decode(r.encoding or "utf-8", errors="replace")
                except LookupError:
                    res.body = bytes(buf).decode("utf-8", errors="replace")
            r.close()
            break
        else:
            res.error = "Too many redirects"
    except BlockedTarget as exc:
        res.error = f"Blocked: {exc}"
    except requests.RequestException as exc:
        res.error = f"Request failed: {type(exc).__name__}: {str(exc)[:200]}"
    except (OSError, ValueError) as exc:
        res.error = f"{type(exc).__name__}: {str(exc)[:200]}"
    finally:
        if r is not None:
            r.close()
        session.close()
    res.elapsed_ms = int((time.time() - started) * 1000)
    return res
