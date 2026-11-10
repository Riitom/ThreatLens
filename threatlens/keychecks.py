"""Structural checks for weak public keys.

These catch *visible* key-generation failures: tiny keys, moduli with small
factors, primes that are too close together. They cannot prove a key is
strong. A key whose algorithm is sound but whose randomness was predictable
(the eMudhra failure involved valid P-384 keys) looks normal on paper, so the
certificate engine also relies on Certificate Transparency, blocklists and the
shared-prime check against previously scanned certificates.
"""
from __future__ import annotations

import math


def _sieve(limit: int) -> list[int]:
    flags = bytearray([1]) * (limit + 1)
    flags[0:2] = b"\x00\x00"
    for i in range(2, int(limit ** 0.5) + 1):
        if flags[i]:
            flags[i * i :: i] = bytearray(len(flags[i * i :: i]))
    return [i for i, f in enumerate(flags) if f]


SMALL_PRIMES = _sieve(10_000)
SAFE_CURVES = {"secp256r1", "secp384r1", "secp521r1"}


def small_factor(n: int) -> int | None:
    for p in SMALL_PRIMES:
        if p * p > n:
            break
        if n % p == 0:
            return p
    return None


def fermat_factorable(n: int, iterations: int = 20_000) -> bool:
    """True if n = p*q with p and q close enough for Fermat's method to find quickly."""
    if n < 9 or n % 2 == 0:
        return n % 2 == 0
    a = math.isqrt(n)
    if a * a == n:
        return True
    a += 1
    for _ in range(iterations):
        b2 = a * a - n
        b = math.isqrt(b2)
        if b * b == b2:
            return a - b > 1
        a += 1
    return False


ROCA_PRIMES = [11, 13, 17, 19, 37, 53, 61, 71, 73, 79, 97, 103, 107, 109, 127, 151, 157]
ROCA_SUBGROUPS = {}
for _p in ROCA_PRIMES:
    _g = 65537 % _p
    _vals = set()
    _cur = 1
    for _ in range(_p):
        _vals.add(_cur)
        _cur = (_cur * _g) % _p
        if _cur == 1:
            break
    ROCA_SUBGROUPS[_p] = _vals


def is_roca_vulnerable(n: int) -> bool:
    """True if RSA modulus n matches the Return of Coppersmith's Attack (ROCA / CVE-2017-15361) fingerprint."""
    if n < (2 ** 512) or n % 2 == 0:
        return False
    for p, valid_residues in ROCA_SUBGROUPS.items():
        if (n % p) not in valid_residues:
            return False
    return True


def check_modulus_entropy(n: int) -> bool:
    """Detect low entropy or repeating byte patterns in RSA modulus."""
    length = (n.bit_length() + 7) // 8
    if length < 128:
        return False
    try:
        n_bytes = n.to_bytes(length, byteorder="big")
    except Exception:
        return False
    for chunk_size in (4, 8, 16):
        chunks = [n_bytes[i: i + chunk_size] for i in range(0, len(n_bytes) - chunk_size, chunk_size)]
        if len(chunks) >= 8 and len(set(chunks)) <= (len(chunks) // 3):
            return True
    return False


def check_rsa(n: int, e: int) -> list[tuple[str, str, str, str]]:
    """Return (id, severity, title, detail) tuples for an RSA public key."""
    issues: list[tuple[str, str, str, str]] = []
    bits = n.bit_length()
    if bits < 1024:
        issues.append(("weak_rsa_size", "critical", f"RSA key is only {bits} bits",
                       "Keys this small can be factored with modest resources."))
    elif bits < 2048:
        issues.append(("weak_rsa_size", "high", f"RSA key is {bits} bits",
                       "Public CAs have required at least 2048 bits for years."))
    if e < 3 or e % 2 == 0:
        issues.append(("bad_rsa_exponent", "critical", f"RSA public exponent {e} is invalid",
                       "The exponent must be odd and at least 3."))
    elif e == 3:
        issues.append(("small_rsa_exponent", "low", "RSA public exponent is 3",
                       "Exponent 3 is legal but fragile with poor padding; 65537 is standard."))
    if n % 2 == 0:
        issues.append(("even_modulus", "critical", "RSA modulus is even",
                       "A valid modulus is the product of two odd primes."))
        return issues
    p = small_factor(n)
    if p is not None:
        issues.append(("small_factor", "critical", f"RSA modulus is divisible by {p}",
                       "A correctly generated modulus has no small prime factors; the key generator is broken."))
    elif fermat_factorable(n):
        issues.append(("close_primes", "critical", "RSA modulus factors with Fermat's method",
                       "The two primes are close together, so anyone can derive the private key from the public key."))
    if is_roca_vulnerable(n):
        issues.append(("roca_vulnerable", "critical", "RSA key is vulnerable to the Return of Coppersmith's Attack (ROCA)",
                       "The modulus matches the Infineon flawed key generator fingerprint (CVE-2017-15361) and can be factored using lattice reduction."))
    return issues
