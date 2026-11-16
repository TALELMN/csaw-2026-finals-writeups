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
