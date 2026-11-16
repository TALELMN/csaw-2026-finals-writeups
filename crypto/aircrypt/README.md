# Aircrypt

| Event | Category | Points | Flag |
|---|---|---|---|
| CSAW CTF Finals 2026 | Crypto | 500 | `csaw{t0ct0u_on_m1cr0tesla_1s_wh4t_fl1es_the_gh0st-49eb93237a6e281a}` |

**TL;DR** — An ADS-B-style transponder feed authenticated with µTESLA, the broadcast
authentication scheme where keys are disclosed *after* the packets they authenticate. The
receiver's loose-time check has a sign error: it accepts a frame whose key has **already been
disclosed**. Lift the disclosed key `K_298` out of the shipped capture, forge a "ghost aircraft"
frame with a valid MAC, and the receiver injects it into the airspace.

---

## 1. Background: why µTESLA normally works

µTESLA authenticates a broadcast stream with symmetric MACs while keeping the key secret from
everyone — including receivers — until it is too late to forge anything:

1. The sender builds a one-way key chain and commits to its tip. Each epoch `e` has key `K_e`.
2. During epoch `e` it broadcasts frames MAC'd under `K_e`. Nobody can verify them yet.
3. One or more epochs later, it **discloses** `K_e`. Receivers verify the chain, then verify the
   buffered frames.

The entire security of the scheme rests on one condition, checked at *receive* time:

> A frame claiming epoch `e` is only acceptable if, when it arrived, `K_e` had **not yet been
> disclosed**.

If that check is wrong, the scheme collapses to "MAC with a published key" — anyone who has seen
the disclosure can mint frames at will.

---

## 2. The bug

The receiver computes its acceptance deadline as:

```c
accept_threshold_us(e)  ==  disclosure_time(e) + SIGMA     // implementation
accept_threshold_us(e)  ==  disclosure_time(e) - SIGMA     // what the spec says
```

`SIGMA` is the clock-skew margin. Subtracting it is conservative: reject anything that could
possibly have arrived after disclosure. **Adding** it does the exact opposite — it extends the
acceptance window *past* the disclosure instant, by the full skew allowance. One character.

That is a time-of-check / time-of-use flaw against the disclosure schedule, which is where the
flag text comes from.

### Concrete numbers

The receiver's clock is pinned at:

```
g_now_us = 151_250_000 µs       (epoch length 500_000 µs  ->  epoch 302.5)
```

Two constraints bound the forgeable epoch:

| Constraint | Meaning | Result |
|---|---|---|
| `t_recv < (e + 5) × 5e5` | the frame has not aged out of the buffer | `e ≥ 298` |
| epoch has started | you cannot claim the future | `e ≤ 302` |

So any `e ∈ [298, 302]` is *accepted* — but we also need to **know** `K_e`, and keys are only
disclosed when `ts ≤ now`. The newest key satisfying both is:

```
K_298, disclosed at ts = 151_000_000 µs — present in the shipped capture trace
```

`K_298` lands in the overlap between "already public" and "still accepted". Without the sign
error that overlap is empty; with it, it is five epochs wide.

---

## 3. Frame and MAC construction

```
Frame (14 bytes):
  DF (0x8D) │ ICAO (3) │ EPOCH (2, big-endian) │ TC_FLAGS (1) │ PAYLOAD (4) │ PI (3)
  └──────────────────── 11 bytes MAC'd ────────────────────┘   └─ tag ─┘

mac_key = SHA3-256(K_epoch ‖ ICAO)[:8]
PI      = HMAC-SHA3-256(mac_key, frame[:11])[:3]
```

Two details worth noting:

- The MAC key is **per-aircraft**, derived from the epoch key and the ICAO address. That stops a
  receiver from replaying one aircraft's frames as another's — but it does not help here,
  because the derivation is public and `K_298` is known, so the key for *any* ICAO, including a
  nonexistent one, is computable.
- The tag is truncated to 3 bytes (24 bits). That is fine when the key is secret and the window
  is short; it is irrelevant once the key is known.

We forge for ICAO `0xDEAD01` — an aircraft that does not exist. The ghost.

---

## 4. Solver

```python
#!/usr/bin/env python3
# solve.py — Aircrypt (CSAW CTF Finals 2026, crypto 500)
#
# TOCTOU in a micro-TESLA receiver: accept_threshold_us(e) returns
# disclosure_time + SIGMA where the spec says - SIGMA, so a frame is accepted
# even after its epoch key has been disclosed.
#
#   Receiver clock is pinned at g_now_us = 151250000 (= epoch 302.5).
#   Accept window: e >= 298 (not aged out) and e <= 302 (epoch has started).
#   Keys are disclosed with ts <= now, so the newest usable key is K_298
#   (disclosed at 151000000) — and it is in the shipped capture trace.
#
# With K_298 known we forge a ghost frame for ICAO 0xDEAD01 and compute its MAC.
#
#   mac_key = SHA3-256(K_epoch || ICAO)[:8]
#   PI (3)  = HMAC-SHA3-256(mac_key, frame[:11])[:3]
#   Frame   = DF(0x8D) ICAO(3) EPOCH(2 BE) TC_FLAGS(1) PAYLOAD(4) PI(3)
#
# usage: python3 solve.py <host> <port> [path/to/trace.txt]
import sys, socket, time, hashlib, hmac, re

TARGET_ICAO = bytes.fromhex("DEAD01")
NOW_US      = 151250000
EPOCH_US    = 500000


def epoch_key_from_trace(trace_path, want_epoch):
    """Disclosed chain key for `want_epoch`, if the trace discloses it at ts <= NOW_US."""
    for line in open(trace_path):
        m = re.match(r'\s*key\s+(\d+)\s+(\d+)\s+([0-9a-fA-F]{32})', line)
        if m:
            ts, ep, keyhex = int(m.group(1)), int(m.group(2)), m.group(3)
            if ep == want_epoch and ts <= NOW_US:
                return bytes.fromhex(keyhex)
    return None


def forge(k_epoch, epoch, payload=b"\x00\x00\x00\x00", tc_flags=0x00):
    mac_key = hashlib.sha3_256(k_epoch + TARGET_ICAO).digest()[:8]
    frame = bytes([0x8D]) + TARGET_ICAO + epoch.to_bytes(2, "big") + bytes([tc_flags]) + payload
    assert len(frame) == 11
    pi = hmac.new(mac_key, frame, hashlib.sha3_256).digest()[:3]
    return (frame + pi).hex()


def main():
    host, port = sys.argv[1], int(sys.argv[2])
    trace = sys.argv[3] if len(sys.argv) > 3 else "share/capture/trace.txt"
    epoch = 298
    k = epoch_key_from_trace(trace, epoch)
    if k is None:
        # fallback: K_298 as disclosed in the shipped capture
        k = bytes.fromhex("f090857b6c65ab0c1a16d389e738620c")
    frame_hex = forge(k, epoch)
    print(f"[*] K_{epoch} = {k.hex()}")
    print(f"[*] forged frame = {frame_hex}")

    s = socket.socket(); s.settimeout(10); s.connect((host, port))
    time.sleep(0.5)
    try: s.recv(4096)          # banner
    except Exception: pass
    s.sendall(frame_hex.encode() + b"\n")
    try: s.shutdown(socket.SHUT_WR)
    except Exception: pass
    time.sleep(0.5)
    data = b""
    try:
        while True:
            d = s.recv(4096)
            if not d: break
            data += d
    except Exception: pass
    s.close()
    out = data.decode("utf-8", "replace")
    print(out)
    m = re.search(r'csaw\{[^}]*\}', out)
    if m: print("[+] FLAG:", m.group())


if __name__ == "__main__":
    main()
```

```
$ python3 solve.py <host> <port> share/capture/trace.txt
[*] K_298 = f090857b6c65ab0c1a16d389e738620c
[*] forged frame = 8ddead01012a00000000<tag>
[+] FLAG: csaw{t0ct0u_on_m1cr0tesla_1s_wh4t_fl1es_the_gh0st-49eb93237a6e281a}
```

---

## Flag

```
csaw{t0ct0u_on_m1cr0tesla_1s_wh4t_fl1es_the_gh0st-49eb93237a6e281a}
```

---

## Takeaways

- **In delayed-disclosure schemes, the clock *is* the key.** µTESLA's MACs are perfectly sound
  here; the only thing standing between an attacker and valid frames is a timestamp comparison,
  and the sign of a margin term flips it from safe to wide open.
- **Skew margins must always be applied in the conservative direction.** `± SIGMA` is the kind of
  error that passes code review and every functional test, because legitimate traffic behaves
  identically either way. Only an attacker notices.
- **Read the disclosure schedule as an attack surface, not as plumbing.** The exploit is entirely
  "which key is simultaneously public and still accepted?" — a question about the window, not
  about the cryptography.
- **A published capture is key material.** The trace shipped as challenge evidence contained the
  disclosed keys; disclosure logs are not benign once the acceptance window is wrong.

## Files

- [`solve.py`](solve.py) — reads `K_298` out of the capture trace, forges the ghost frame, submits it.

> **Writeup provenance.** This page was reconstructed from the working solver and its analysis
> notes; the flag was produced live by the script above.
