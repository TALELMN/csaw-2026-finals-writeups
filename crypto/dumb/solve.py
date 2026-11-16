#!/usr/bin/env python3
# solve.py — "dumb" (CSAW): XOR-shared RSA public keys; one of them opens the flag.
import base64
import re
import socket
import string
import sys
from functools import reduce

import numpy as np

HOST = sys.argv[1] if len(sys.argv) > 1 else "10.0.208.192"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 8000


class Remote:
    def __init__(self):
        self.s = socket.create_connection((HOST, PORT), timeout=10)
        self.until()

    def until(self, end=b"> "):
        buf = b""
        while not buf.endswith(end):
            d = self.s.recv(65536)
            if not d:
                break
            buf += d
        return buf

    def cmd(self, line):
        self.s.sendall(line + b"\n")
        return self.until()


def xor_all(blobs):
    return reduce(lambda a, b: bytes(p ^ q for p, q in zip(a, b)), blobs)


def subsets_xor(rows):
    """All 2^len(rows) subset XORs; index bit k set <=> rows[k] is in the subset."""
    acc = np.zeros((1, rows.shape[1]), np.uint8)
    for row in rows:
        acc = np.concatenate([acc, acc ^ row])
    return acc


r = Remote()
frags = [base64.b64decode(l) for l in r.cmd(b"1").decode().split("\n") if len(l) > 100]
assert len(frags) == 21 and all(len(f) == 800 for f in frags)

# Meet in the middle: find every subset whose XOR is base64 text inside the PEM body.
ok = np.zeros(256, bool)
ok[list((string.ascii_letters + string.digits + "+/=\n").encode())] = True
win = np.array([list(f[92:132]) for f in frags], dtype=np.uint8)
left, right = subsets_xor(win[:11]), subsets_xor(win[11:])

keys = []
for i, l in enumerate(left):
    for j in np.nonzero(ok[right ^ l].all(axis=1))[0]:
        idx = [k for k in range(11) if i >> k & 1] + [11 + k for k in range(10) if int(j) >> k & 1]
        pem = xor_all([frags[k] for k in idx])
        if pem.startswith(b"-----BEGIN PUBLIC KEY-----"):
            keys.append((idx, pem))
print(f"[+] recovered {len(keys)} public keys")

# Offer each recovered key to "open"; only one is accepted.
for idx, pem in keys:
    r.cmd(b"2")
    out = r.cmd(base64.b64encode(pem)).decode()
    m = re.search(r"csaw\{[^}]*\}", out)
    print(f"    fragments {idx}: {m.group(0) if m else 'no'}")
    if m:
        print("[+] flag:", m.group(0))
        break
