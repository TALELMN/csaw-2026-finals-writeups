# dumb

| Event | Category | Flag |
|---|---|---|
| CSAW CTF Finals 2026 | Crypto | `csaw{1_th1nk_1m_d4mb_m4yb3_j4st_h4ppy}` |

**TL;DR** — A TCP service hands out 21 random-looking "fragments" and asks for a key to `open`
the flag. The fragments are XOR shares of three RSA-4096 public keys. Recover the keys with a
meet-in-the-middle over the 2²¹ subsets and submit the right one. **No RSA weakness is
involved** — the name is the hint.

---

## 1. Recognising the fragments as XOR shares

The menu offers `1 fragments`, `2 open`, `3 encrypt`. Option 1 returns 21 base64 lines, each
decoding to 800 bytes, identical across connections.

Four observations, in the order they matter:

1. Each fragment looks uniformly random on its own — so none is a key by itself.
2. XORing **all 21** gives a valid `-----BEGIN PUBLIC KEY-----` header, intact newlines and a
   valid footer — but a garbled body.
3. 800 bytes is exactly the size of a PEM-encoded RSA-4096 public key.
4. A clean header with a garbled body means an **odd number of PEM keys** are XORed together.

Point 4 is the whole insight. All PEM keys share the identical header, footer and line breaks.
XOR an even number of them and those constant regions cancel to zeros; XOR an odd number and one
copy survives intact, while the bodies — which differ — turn to noise. Seeing a *perfect*
header over a garbled body is therefore a direct readout of the parity of the share count.

So some subsets of the fragments XOR to individual keys, and we only need to find which.

---

## 2. Recovering the keys

2²¹ ≈ 2.1 million subsets is small, and a meet-in-the-middle makes it trivial: split into the
first 11 and last 10 fragments, enumerate both halves' XORs (2048 and 1024 rows), and look for
pairs whose combined XOR is plausible.

The test: take a 40-byte window inside the PEM body (bytes 92–132) and require **every byte to
be a base64 character**. Random noise fails this instantly (each byte has roughly a 1-in-4
chance of passing, so 40 bytes is overwhelming evidence), while a real PEM passes by
construction. NumPy broadcasting does the whole cross-product at once.

Exactly three subsets pass. They are **disjoint** and each contains **7** fragments — 3 × 7 = 21,
confirming the construction completely:

| Fragments | Result of `open` |
|---|---|
| 8, 12, 15, 16, 17, 18, 19 | **flag** |
| 0, 1, 3, 4, 9, 14, 20 | `no` |
| 2, 5, 6, 7, 10, 11, 13 | `no` |

`open` expects the PEM on one line, base64-encoded — the same encoding the fragments arrive in.
The `encrypt` option (RSA-OAEP-SHA256 under any supplied public key) is a red herring for the
attack itself, but it is useful for one thing: confirming the exact input format the server
accepts, before you spend attempts guessing.

---

## 3. Solver

```python
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
```

Output against the live instance:

```
[+] recovered 3 public keys
    fragments [8, 12, 15, 16, 17, 18, 19]: csaw{1_th1nk_1m_d4mb_m4yb3_j4st_h4ppy}
[+] flag: csaw{1_th1nk_1m_d4mb_m4yb3_j4st_h4ppy}
```

Requires Python 3 with `numpy`, and the challenge WireGuard tunnel up.

---

## Flag

```
csaw{1_th1nk_1m_d4mb_m4yb3_j4st_h4ppy}
```

---

## Takeaways

- **Structured plaintext leaks through XOR.** Fixed PEM headers mean the XOR of a set of keys
  advertises the parity of the set. Secret sharing over data with constant regions is not
  information-theoretically hiding in practice.
- **A 40-byte alphabet check is a razor-sharp oracle.** You do not need to parse ASN.1 to know
  whether a candidate is a real PEM.
- **2^21 is not a search space, but reflexes matter.** Meet-in-the-middle turns 2M full 800-byte
  XORs into 3k 40-byte ones.
- **Not every crypto challenge has a crypto vulnerability.** There is nothing wrong with the RSA
  here; the bug is in how the keys were distributed.

## Files

- [`solve.py`](solve.py) — recovers all three keys and submits them to `open`.
