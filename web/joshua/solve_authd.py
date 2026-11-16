#!/usr/bin/env python3
# solve_authd.py — runs ON the target box. Forges an admin token for authd.
import socket, struct, time, sys

SBOX = [0x06,0x04,0x0c,0x05, 0x00,0x07,0x02,0x0e, 0x01,0x0f,0x03,0x0d, 0x08,0x0a,0x09,0x0b]
CRYPT_KEY = 0x53757070446573a7      # immediates read out of handle_client
MAC_KEY   = 0xde57c0ffee1234b9
M32 = 0xffffffff
def rol32(x, n): return ((x << n) | (x >> (32 - n))) & M32

def perm(x):                        # joshua_P: keyless permutation, also crypt's core
    x &= M32; sch = 0x9e3779b9
    while True:
        o = 0
        for c in range(0, 32, 4):
            o |= SBOX[(x >> c) & 0xf] << c
        o = rol32(o, 7); x = o ^ sch; sch = (sch + 0x7f4a7c15) & M32
        if sch == 0x1c16edf8:
            return x & M32

def keystream_word(nonce, i):       # joshua_crypt, word i
    kh = (CRYPT_KEY >> 32) & M32; kl = CRYPT_KEY & M32
    return (kl ^ perm(((nonce ^ kh) + i) & M32)) & M32

def crypt(nonce, buf16):            # token cipher: XOR stream over 4 words
    out = bytearray(buf16)
    for i in range(4):
        w = struct.unpack_from('<I', out, i * 4)[0] ^ keystream_word(nonce, i)
        struct.pack_into('<I', out, i * 4, w & M32)
    return bytes(out)

def jstream(key, data):             # joshua_stream: the flag.enc cipher
    kh = ((key >> 32) & M32) ^ 0xC0FFEE; kl = key & M32
    out = bytearray(data)
    for blk in range(0, len(out), 4):
        ks = perm(((blk >> 2) + kh) & M32) ^ kl
        for j in range(4):
            if blk + j < len(out):
                out[blk + j] ^= (ks >> (8 * j)) & 0xff
    return bytes(out)

SOCK = "/tmp/joshua/authd.sock"
def frame(cmd, payload=b""):
    return bytes([cmd]) + struct.pack('<H', len(payload)) + payload

def main():
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.connect(SOCK)
    def sendrecv(cmd, payload=b"", n=256):
        s.sendall(frame(cmd, payload)); time.sleep(0.05)
        try: return s.recv(n)
        except Exception: return b""

    # 1) hello -> session_id (== initial challenge c0); arms the 12s window
    r = sendrecv(1); sid = struct.unpack_from('<I', r, 3)[0]
    print("[*] hello resp", r.hex(), "sid=%08x" % sid)

    # 2) handshake: 4 rounds of the self-computable chain c_{i+1} = P(c_i)
    c = sid
    for rnd in range(4):
        resp = perm(c); rr = sendrecv(3, struct.pack('<I', resp))
        print("[*] round", rnd + 1, "resp=%08x" % resp, rr.hex()); c = resp

    # 3) issue a guest token and decrypt it (sanity: role=0, expiry=now+300)
    tok = sendrecv(2)[3:3 + 28]
    nonce = struct.unpack_from('<I', tok, 0)[0]; enc = tok[4:20]; mac = tok[20:28]
    rec = crypt(nonce, enc)
    print("[*] guest token", tok.hex())
    print("[*] guest record", rec.hex(),
          "role=%d expiry=%d now=%d" % (rec[0], struct.unpack_from('<I', rec, 4)[0], int(time.time())))

    # 4) forge: role -> 1, re-encrypt word 0, keep nonce + MAC (word 0 is not MAC'd)
    frec = bytearray(rec); frec[0] = 1
    ftok = tok[0:4] + crypt(nonce, bytes(frec)) + mac
    print("[*] forged token", ftok.hex())

    # 5) submit -> response = frame[3] + key[8] + flag.enc[...]
    fr = sendrecv(4, ftok, 4096)
    print("[*] verify resp len", len(fr))
    if len(fr) < 12:
        print("[!] denied / short response:", fr.hex()); return
    key  = struct.unpack_from('<Q', fr, 3)[0]   # 8-byte joshua_stream key, little-endian
    blob = fr[11:]
    pt   = jstream(key, blob)
    import re; m = re.search(rb'csaw\{[^}]*\}', pt)
    sys.stdout.buffer.write(b"[*] decrypted:\n" + pt + b"\n")
    print("[+] FLAG:", m.group().decode() if m else "<not found>")

main()
