"""Certificate and trust-chain validation.

Checks performed on every certificate the server presents (leaf *and*
intermediates, because the eMudhra incident was in intermediate CAs):

* chain validation against the system trust store (plus an optional extra CA file)
* hostname match, expiry, validity length, signature algorithm
* key strength and structural weakness (see keychecks.py)
* blocklisted public keys and CAs under public incident review
* shared RSA prime factors with previously scanned certificates
* Certificate Transparency: embedded SCTs and, optionally, a crt.sh lookup
"""
from __future__ import annotations

import datetime as dt
import hashlib
import ipaddress
import json
import re
import socket
import ssl
from functools import lru_cache

import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from . import config, keychecks, netsafe
from .models import Finding

_VERIFY_CODES = {10: "expired", 9: "not_yet_valid", 18: "self_signed", 19: "self_signed_chain",
                 20: "unknown_issuer", 21: "unknown_issuer", 62: "hostname_mismatch"}


@lru_cache(maxsize=1)
def _distrust() -> dict:
    try:
        return json.loads((config.DATA_DIR / "distrusted.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"blocked_spki_sha256": [], "issuer_watch": []}


# --------------------------------------------------------------------------- fetching the chain
def _chain_der(sock: ssl.SSLSocket, verified: bool) -> list[bytes]:
    getter = sock.get_verified_chain if verified else sock.get_unverified_chain
    chain = []
    for item in getter() or []:
        chain.append(item if isinstance(item, (bytes, bytearray)) else item.public_bytes(ssl._ssl.ENCODING_DER))
    if not chain:
        leaf = sock.getpeercert(binary_form=True)
        chain = [leaf] if leaf else []
    return [bytes(c) for c in chain]


def fetch_chain(host: str, port: int = 443, timeout: int | None = None) -> dict:
    if not (config.any_port() or config.allow_private()) and port not in config.ALLOWED_PORTS:
        raise netsafe.BlockedTarget(f"Port {port} is not on the scanner's allowed list")
    timeout = timeout or config.fetch_timeout()
    addresses = [ip for _fam, ip in netsafe.resolve_public(host, port)]
    server_name = host.strip("[]")
    ip = addresses[0]

    def connect(ctx: ssl.SSLContext):
        nonlocal ip
        raw, last = None, None
        for candidate in addresses:  # every address was already validated as public
            try:
                raw = socket.create_connection((candidate, port), timeout=timeout)
                ip = candidate
                break
            except OSError as exc:
                last = exc
        if raw is None:
            raise last or OSError("connection failed")
        try:
            return ctx.wrap_socket(raw, server_hostname=server_name)
        except Exception:
            raw.close()
            raise

    try:
        import certifi
        ca_bundle = certifi.where()
    except Exception:
        ca_bundle = None

    if ca_bundle and not config.extra_ca_file():
        ctx = ssl.create_default_context(cafile=ca_bundle)
    else:
        ctx = ssl.create_default_context()
    if config.extra_ca_file():
        ctx.load_verify_locations(cafile=config.extra_ca_file())
    out = {"verified": False, "verify_error": None, "verify_code": None, "chain": [], "protocol": None, "cipher": None, "ip": None}
    try:
        with connect(ctx) as s:
            out.update(verified=True, chain=_chain_der(s, True), protocol=s.version(), cipher=(s.cipher() or [None])[0], ip=ip)
        return out
    except ssl.SSLCertVerificationError as exc:
        out["verify_error"] = exc.verify_message or str(exc)
        out["verify_code"] = exc.verify_code
    # Untrusted: connect again without verification just to read what was presented.
    loose = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    loose.check_hostname = False
    loose.verify_mode = ssl.CERT_NONE
    with connect(loose) as s:
        out.update(chain=_chain_der(s, False), protocol=s.version(), cipher=(s.cipher() or [None])[0], ip=ip)
    return out


# --------------------------------------------------------------------------- helpers
def _name(cert_name: x509.Name, oid) -> str:
    attrs = cert_name.get_attributes_for_oid(oid)
    return attrs[0].value if attrs else ""


def _sans(cert: x509.Certificate) -> tuple[list[str], list[str]]:
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        return san.get_values_for_type(x509.DNSName), [str(i) for i in san.get_values_for_type(x509.IPAddress)]
    except x509.ExtensionNotFound:
        return [], []


def host_matches(host: str, dns_names: list[str], ips: list[str]) -> bool:
    host = host.strip("[]").lower().rstrip(".")
    try:
        literal = ipaddress.ip_address(host)
        return str(literal) in ips
    except ValueError:
        pass
    for pattern in dns_names:
        pattern = pattern.lower().rstrip(".")
        if pattern == host:
            return True
        if pattern.startswith("*.") and host.count(".") == pattern.count(".") and host.split(".", 1)[1] == pattern[2:]:
            return True
    return False


def _spki_hash(cert: x509.Certificate) -> str:
    der = cert.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(der).hexdigest()


def _describe_key(pub) -> tuple[str, str, int | None]:
    if isinstance(pub, rsa.RSAPublicKey):
        return "RSA", f"RSA {pub.key_size}", pub.key_size
    if isinstance(pub, ec.EllipticCurvePublicKey):
        return "EC", f"EC {pub.curve.name}", pub.curve.key_size
    if isinstance(pub, ed25519.Ed25519PublicKey):
        return "Ed25519", "Ed25519", 256
    if isinstance(pub, ed448.Ed448PublicKey):
        return "Ed448", "Ed448", 448
    if isinstance(pub, dsa.DSAPublicKey):
        return "DSA", f"DSA {pub.key_size}", pub.key_size
    return "other", type(pub).__name__, None


def _ct_lookup(host: str, leaf: x509.Certificate) -> bool | None:
    """True/False if crt.sh answered, None if it could not be queried."""
    try:
        r = requests.get("https://crt.sh/", params={"q": host, "output": "json", "exclude": "expired"},
                         timeout=config.fetch_timeout(), headers={"User-Agent": netsafe.USER_AGENT})
        r.raise_for_status()
        serial = leaf.serial_number
        for row in r.json():
            try:
                if int(str(row.get("serial_number", "")), 16) == serial:
                    return True
            except ValueError:
                continue
        return False
    except Exception:
        return None


# --------------------------------------------------------------------------- main entry
def analyze_certificate(host: str, port: int = 443, store=None, ct_lookup: bool | None = None,
                        fetched: dict | None = None) -> tuple[list[Finding], dict]:
    findings: list[Finding] = []

    def add(fid, sev, title, detail="", advice="", axis="both", weight=None, posture_weight=None, floor=None):
        findings.append(Finding(f"cert.{fid}", "certificate", axis, sev, title, detail, advice, weight, posture_weight, floor))

    got = fetched or fetch_chain(host, port)
    certs = [x509.load_der_x509_certificate(d) for d in got["chain"]]
    if not certs:
        raise ValueError("Server presented no certificate")
    leaf = certs[0]
    now = dt.datetime.now(dt.timezone.utc)
    dns_names, ip_sans = _sans(leaf)
    self_signed = len(certs) == 1 and leaf.issuer == leaf.subject
    nb, na = leaf.not_valid_before_utc, leaf.not_valid_after_utc
    days_left = (na - now).days
    validity_days = (na - nb).days
    key_type, key_label, _ = _describe_key(leaf.public_key())
    sig = leaf.signature_hash_algorithm.name if leaf.signature_hash_algorithm else "eddsa"
    issuer_org = _name(leaf.issuer, NameOID.ORGANIZATION_NAME) or _name(leaf.issuer, NameOID.COMMON_NAME)

    # ---- trust ---------------------------------------------------------------
    reason = _VERIFY_CODES.get(got.get("verify_code"), "other")
    if not got["verified"]:
        msgs = {
            "expired": ("medium", "Certificate has expired", "Browsers show a full-page warning for expired certificates.", 18),
            "not_yet_valid": ("high", "Certificate is not valid yet", "The certificate's start date is in the future.", 40),
            "self_signed": ("high", "Certificate is self-signed", "No trusted authority vouches for this site's identity.", 40),
            "self_signed_chain": ("high", "Chain ends in an untrusted self-signed root", "The issuing root is not in the trust store.", 40),
            "unknown_issuer": ("high", "Certificate chain does not lead to a trusted authority",
                               "The issuer is unknown, the chain is incomplete, or the CA has been distrusted.", 40),
            "hostname_mismatch": ("high", "Certificate was issued for a different domain",
                                  f"It covers {', '.join(dns_names[:4]) or 'other names'}, not {host}.", 40),
            "other": ("high", "Certificate failed validation", got.get("verify_error") or "", 40),
        }
        sev, title, detail, w = msgs[reason]
        add("untrusted", sev, title, detail, "Do not proceed past a browser certificate warning on a site that asks for credentials.", weight=w)
    elif not host_matches(host, dns_names, ip_sans):  # verified by OpenSSL but double-check
        add("hostname_mismatch", "high", "Certificate does not list this host", f"Covers: {', '.join(dns_names[:4])}", weight=40)

    # ---- dates and lifetime -----------------------------------------------------
    if days_left < 0 and reason != "expired":
        add("expired", "medium", "Certificate has expired", f"Expired {-days_left} days ago.", weight=18)
    elif 0 <= days_left <= 14:
        add("expiring_soon", "medium", f"Certificate expires in {days_left} days", axis="posture", weight=0, posture_weight=8)
    if validity_days > 398 and not self_signed:
        add("long_validity", "low", f"Certificate lifetime is {validity_days} days",
            "Publicly trusted certificates have been limited to 398 days or fewer since 2020, and the limit keeps shrinking.",
            axis="posture", weight=0, posture_weight=6)
    age_days = (now - nb).days
    if 0 <= age_days <= 3 and not self_signed:
        add("brand_new", "low", "Certificate was issued within the last 3 days",
            "Phishing sites usually get certificates just before launch. New certificates are also normal for new sites.", axis="threat", weight=7)

    # ---- algorithms ---------------------------------------------------------------
    if sig in ("md5", "sha1"):
        add("weak_signature", "high", f"Certificate signed with {sig.upper()}", "Collision attacks make forged certificates feasible.",
            weight=18, posture_weight=25)
    try:
        eku = leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        if ExtendedKeyUsageOID.SERVER_AUTH not in eku:
            add("wrong_eku", "high", "Certificate is not valid for TLS server authentication", weight=30)
    except x509.ExtensionNotFound:
        pass

    # ---- key strength, every certificate in the chain -------------------------
    blocked = set(_distrust().get("blocked_spki_sha256", []))
    chain_info = []
    for idx, cert in enumerate(certs):
        role = "leaf" if idx == 0 else "intermediate"
        subj = _name(cert.subject, NameOID.COMMON_NAME) or _name(cert.subject, NameOID.ORGANIZATION_NAME) or "unnamed"
        try:
            pub = cert.public_key()
        except Exception:
            add("unreadable_key", "high", f"Public key in {role} certificate '{subj}' could not be parsed", weight=30)
            continue
        ktype, klabel, _bits = _describe_key(pub)
        spki = _spki_hash(cert)
        chain_info.append({"role": role, "subject": subj,
                           "issuer": _name(cert.issuer, NameOID.COMMON_NAME) or _name(cert.issuer, NameOID.ORGANIZATION_NAME),
                           "key": klabel, "spki_sha256": spki,
                           "not_after": cert.not_valid_after_utc.date().isoformat()})
        where = f"{role} certificate '{subj}'"
        if spki in blocked:
            add("blocked_key", "critical", f"Public key of {where} is on the distrust list",
                "This key has been marked as untrustworthy; certificates built on it can be forged.", weight=65, floor=85)
        if isinstance(pub, rsa.RSAPublicKey):
            nums = pub.public_numbers()
            for fid, sev, title, detail in keychecks.check_rsa(nums.n, nums.e):
                crit = sev == "critical"
                add(fid, sev, f"{title} in {where}", detail, weight=65 if crit else None, floor=85 if crit else None)
            if store is not None:
                clash = store.find_shared_prime(nums.n, spki)
                if clash:
                    add("shared_prime", "critical", f"RSA modulus of {where} shares a prime factor with another certificate",
                        f"It shares a factor with a key previously seen for '{clash['subject']}'. Both private keys can be computed.",
                        weight=65, floor=85)
                store.record_key(spki, "RSA", format(nums.n, "x"), subj, chain_info[-1]["issuer"])
        elif isinstance(pub, ec.EllipticCurvePublicKey):
            if pub.curve.name not in keychecks.SAFE_CURVES:
                add("weak_curve", "medium", f"{where} uses uncommon curve {pub.curve.name}",
                    "Browsers only support the NIST P-256, P-384 and P-521 curves for web PKI.", weight=18)
            if store is not None:
                store.record_key(spki, "EC", None, subj, chain_info[-1]["issuer"])
        elif isinstance(pub, dsa.DSAPublicKey):
            add("dsa_key", "high", f"{where} uses a DSA key", "DSA is deprecated for the web PKI.", weight=30)

    # ---- CAs under review ---------------------------------------------------------
    for cert in certs:
        names = " ".join([cert.issuer.rfc4514_string(), cert.subject.rfc4514_string()]).lower()
        for rule in _distrust().get("issuer_watch", []):
            if re.search(rule["pattern"], names):
                add("issuer_watch", "low" if got["verified"] else "high",
                    "Chain includes a CA that is under public incident review", rule["note"],
                    "Compare against current browser distrust lists before relying on this chain.",
                    weight=7 if got["verified"] else 40)
                break
        else:
            continue
        break

    # ---- Certificate Transparency -----------------------------------------------
    sct_count = 0
    try:
        sct_count = len(leaf.extensions.get_extension_for_class(x509.PrecertificateSignedCertificateTimestamps).value)
    except x509.ExtensionNotFound:
        pass
    ct_state = {"embedded_scts": sct_count, "crtsh": None}
    if got["verified"] and not self_signed and sct_count == 0:
        add("no_sct", "medium", "No Certificate Transparency proof embedded in the certificate",
            "Public CAs have logged every browser-trusted certificate since 2018. A certificate that was never logged cannot be monitored "
            "by the domain owner, which is how a mis-issued certificate could go unnoticed. SCTs can also arrive via OCSP or a TLS "
            "extension, which this scan does not read.", weight=12, posture_weight=8)
    do_ct = config.ct_lookup_enabled() if ct_lookup is None else ct_lookup
    if do_ct and got["verified"] and not self_signed:
        found = _ct_lookup(host, leaf)
        ct_state["crtsh"] = {True: "found", False: "not_found", None: "unavailable"}[found]
        if found is False:
            add("not_in_ct_logs", "high", "Certificate was not found in public Certificate Transparency logs",
                "crt.sh has no record of this serial number for the host. Logs can lag by minutes, but an old certificate "
                "missing from them is a strong sign of irregular issuance.", weight=30)

    info = {
        "host": host, "port": port, "ip": got.get("ip"), "trusted": got["verified"],
        "trust_error": got.get("verify_error"), "protocol": got.get("protocol"), "cipher": got.get("cipher"),
        "subject_cn": _name(leaf.subject, NameOID.COMMON_NAME), "issuer": issuer_org, "san": dns_names[:25] + ip_sans,
        "not_before": nb.isoformat(), "not_after": na.isoformat(), "days_left": days_left, "validity_days": validity_days,
        "key": key_label, "signature": sig, "self_signed": self_signed,
        "sha256": leaf.fingerprint(hashes.SHA256()).hex(), "serial": format(leaf.serial_number, "x"),
        "transparency": ct_state, "chain": chain_info,
    }
    if got.get("protocol") == "TLSv1.2":
        add("no_tls13", "low", "Server negotiated TLS 1.2; TLS 1.3 was not offered", axis="posture", weight=0, posture_weight=3)
    return findings, info


def analyze_pem_text(pem_text: str, host: str = "custom.domain", store=None) -> tuple[list[Finding], dict]:
    """Parse and cryptographically analyze an X.509 certificate or chain provided in PEM text format."""
    blocks = re.findall(r"-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----", pem_text)
    if not blocks:
        raise ValueError("No valid PEM certificate found (missing -----BEGIN CERTIFICATE-----)")
    der_list = []
    for b in blocks:
        cert = x509.load_pem_x509_certificate(b.encode("utf-8"))
        der_list.append(cert.public_bytes(serialization.Encoding.DER))

    leaf = x509.load_der_x509_certificate(der_list[0])
    dns_names, ip_sans = _sans(leaf)
    target_host = host if host != "custom.domain" else (dns_names[0] if dns_names else "custom.domain")
    is_self = len(der_list) == 1 and leaf.issuer.rfc4514_string() == leaf.subject.rfc4514_string()

    fake_fetched = {
        "verified": False,
        "verify_error": "Analyzed from raw PEM; verify against system root trust store",
        "verify_code": 18 if is_self else 20,
        "chain": der_list,
        "protocol": None,
        "cipher": None,
        "ip": "PEM-Direct"
    }
    return analyze_certificate(target_host, 443, store=store, ct_lookup=False, fetched=fake_fetched)
