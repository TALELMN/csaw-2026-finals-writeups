#!/usr/bin/env python3
"""Beeseal (CSAW CTF Finals 2026, crypto 500) — ECDSA biased-nonce key recovery.

The signer drew nonces from [1, 2^248) instead of [1, n), leaving the top 8 bits
of every nonce zero. That turns key recovery into a Hidden Number Problem:

    s_i * k_i = z_i + d * r_i  (mod n)
    =>  k_i = a_i * d + b_i    (mod n),   a_i = r_i/s_i, b_i = z_i/s_i

With every k_i < B = 2^248, the vector (k_1..k_N, d*B, n*B) is unusually short in
the Boneh-Venkatesan lattice below, so reduction recovers it. Some signatures in
the handout are deliberately corrupted, so invalid ones are filtered structurally
(r must be the x-coordinate of a real curve point) and the attack is then run on
random subsets, verifying each candidate against the public key.

Usage:
    python3 solve.py signatures.json pubkey.pem flag.enc

Dependencies: fpylll, cysignals, ecdsa, cryptography

Reconstruction note: this script reimplements the documented method; the original
competition scripts (check.py / hnp.py) were not preserved. The recovered key is
    d = 0xc8356b99f1e3abbc58bf973f82caabdd2444e2cbf3d71b666172b1fd8a92c29a
so the decryption half can be checked on its own with --d.
"""
import argparse
import hashlib
import json
import random
import sys

# NIST P-256 domain parameters.
P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
A = P - 3
B_COEF = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
GX = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
GY = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5

B_BOUND = 1 << 248          # nonce bound: the whole vulnerability


# --- minimal short-Weierstrass arithmetic, enough to verify d*G == Q ---------

def point_add(p, q):
    if p is None:
        return q
    if q is None:
        return p
    if p[0] == q[0] and (p[1] + q[1]) % P == 0:
        return None
    if p == q:
        lam = (3 * p[0] * p[0] + A) * pow(2 * p[1], -1, P) % P
    else:
        lam = (q[1] - p[1]) * pow(q[0] - p[0], -1, P) % P
    x = (lam * lam - p[0] - q[0]) % P
    return (x, (lam * (p[0] - x) - p[1]) % P)


def point_mul(k, p=(GX, GY)):
    r = None
    while k:
        if k & 1:
            r = point_add(r, p)
        p = point_add(p, p)
        k >>= 1
    return r


def on_curve_x(x):
    """True if x is the x-coordinate of a real P-256 point (y^2 is a QR mod p)."""
    rhs = (pow(x, 3, P) + A * x + B_COEF) % P
    return rhs == 0 or pow(rhs, (P - 1) // 2, P) == 1


# --- the lattice attack ------------------------------------------------------

def build_basis(pairs):
    """Boneh-Venkatesan / Howgrave-Graham-Smart basis for N (a_i, b_i) pairs."""
    n = len(pairs)
    basis = [[0] * (n + 2) for _ in range(n + 2)]
    for i in range(n):
        basis[i][i] = N * N
    for i, (a, _) in enumerate(pairs):
        basis[n][i] = N * a
    basis[n][n] = B_BOUND
    for i, (_, b) in enumerate(pairs):
        basis[n + 1][i] = N * b
    basis[n + 1][n + 1] = N * B_BOUND
    return basis


def candidates_from(pairs, bkz_block=20):
    """Reduce the lattice and yield every plausible private key from its rows."""
    from fpylll import IntegerMatrix, LLL, BKZ

    n = len(pairs)
    m = IntegerMatrix.from_matrix(build_basis(pairs))
    LLL.reduction(m)
    BKZ.reduction(m, BKZ.Param(bkz_block))
    inv_b = pow(B_BOUND, -1, N)
    for row in range(m.nrows):
        v = m[row][n]
        if v == 0:
            continue
        for sign in (1, -1):
            yield (sign * v % N) * inv_b % N


def recover_key(sigs, pub, subset_size=40, tries=200, seed=0):
    """Run the attack on random clean-looking subsets until d*G == Q."""
    rng = random.Random(seed)
    for attempt in range(1, tries + 1):
        subset = rng.sample(sigs, min(subset_size, len(sigs)))
        pairs = []
        for z, r, s in subset:
            s_inv = pow(s, -1, N)
            pairs.append((r * s_inv % N, z * s_inv % N))
        for d in candidates_from(pairs):
            if d and point_mul(d) == pub:
                print(f"[+] subset {attempt}: d = {hex(d)}")
                return d
        print(f"[-] subset {attempt}: no candidate verified", file=sys.stderr)
    return None


# --- I/O ---------------------------------------------------------------------

def load_signatures(path):
    """Read (z, r, s) triples, dropping records whose r is not a curve x-coordinate."""
    raw = json.loads(open(path).read())
    kept, dropped = [], []
    for i, rec in enumerate(raw):
        msg = rec["msg"]
        msg = bytes.fromhex(msg) if isinstance(msg, str) else bytes(msg)
        z = int.from_bytes(hashlib.sha256(msg).digest(), "big") % N
        r = int(rec["r"], 16) if isinstance(rec["r"], str) else int(rec["r"])
        s = int(rec["s"], 16) if isinstance(rec["s"], str) else int(rec["s"])
        if on_curve_x(r):
            kept.append((z, r, s))
        else:
            dropped.append(i)
    print(f"[*] {len(kept)} structurally valid signatures, dropped {dropped}")
    return kept


def load_pubkey(path):
    from cryptography.hazmat.primitives.serialization import load_pem_public_key
    nums = load_pem_public_key(open(path, "rb").read()).public_numbers()
    return (nums.x, nums.y)


def decrypt_flag(d, enc_path):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.hashes import SHA256
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    enc = open(enc_path, "rb").read()
    key = HKDF(SHA256(), 32, None, b"cirrus-manifest-seal").derive(d.to_bytes(32, "big"))
    return AESGCM(key).decrypt(enc[:12], enc[12:], None)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("signatures", nargs="?", default="signatures.json")
    ap.add_argument("pubkey", nargs="?", default="pubkey.pem")
    ap.add_argument("enc", nargs="?", default="flag.enc")
    ap.add_argument("--d", help="skip the lattice attack and use this private key (hex)")
    args = ap.parse_args()

    if args.d:
        d = int(args.d, 16)
    else:
        d = recover_key(load_signatures(args.signatures), load_pubkey(args.pubkey))
        if d is None:
            sys.exit("[!] no subset yielded a verified key; raise --tries or subset size")

    print("[+] flag:", decrypt_flag(d, args.enc).decode())


if __name__ == "__main__":
    main()
