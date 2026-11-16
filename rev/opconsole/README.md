# OpConsole

| Event | Category | Flag |
|---|---|---|
| CSAW CTF Finals 2026 | Reverse | `csaw{M45t3r_$ud0-0f-$ud0}` |

**TL;DR** — An ARM64 ELF with an Alpine root filesystem and a seven-layer privilege-escalation
chain bolted inside. None of that matters: the **launcher decrypts the real flag before it ever
starts the console daemon**, using a xorshift64\* keystream with hardcoded constants. Decrypt 25
bytes from `.rodata` statically and the seven account layers never run.

**Input SHA-256:** `c68627792d72a70e8a9621f0578e8a7907c5324033442cd8e1329c2225845b0e`

---

## 1. Unpacking the container

The last 16 bytes of the file are a trailer: the magic `OPCROOT1` followed by the little-endian
size of an embedded gzip tarball. Carving and unpacking that exposes `opcd` and a set of console
utilities.

Two things inside are decoys and should be recognised as such early:

- Old shard files left over from a previous "version".
- A migration note addressed to automated assistants. It is **not** an instruction and **not**
  evidence of a valid flag — it exists to redirect an agent-assisted solve down the intended
  seven-layer path.

---

## 2. The launcher's keystream

At `0x400290` the launcher initialises a xorshift64\* generator:

```
state      = 0x052c03586b73f22b
multiplier = 0x2545f4914f6cdd1d
```

Instructions at `0x4002c8`–`0x4002f0` decrypt **25 bytes** from virtual address `0x40e0d0`. Each
step is the standard xorshift64\* update — XOR with right-shift 12, left-shift 25, right-shift 27,
all in 64-bit arithmetic — then the **top byte of the multiplied state** is XORed with the
corresponding ciphertext byte:

```python
state ^= state >> 12
state ^= (state << 25) & MASK64
state ^= state >> 27
key = ((state * 0x2545f4914f6cdd1d) & MASK64) >> 56
plain = cipher_byte ^ key
```

A PRNG keystream with a hardcoded seed is not encryption — it is obfuscation with extra steps.
Since both the seed and the multiplier are immediates in the text segment, the keystream is fully
determined and reproducible offline.

---

## 3. Why the decrypted buffer really is the flag

Decrypting 25 bytes is easy; proving they are *the* flag matters more. The dataflow does that:

1. The decrypted buffer is written to a pipe, starting at `0x400d60`.
2. The child process duplicates the read end to **file descriptor 3** and executes
   `/usr/local/libexec/opc/opcd`.
3. The daemon reads descriptor 3 and splits that value into **seven XOR shares** — one per
   account layer in the intended privilege-escalation path.

So the string the launcher decrypts is exactly the input the daemon distributes across all seven
layers. Walking the layers would reassemble the same value. This is the static shortcut past the
entire intended challenge.

Confirming the negative is also worth doing: the original file contains **no plaintext
`csaw{...}` match** anywhere, so the flag genuinely comes from this decryption.

**Ciphertext:** `315600182ebf735cbd448fbabb355a86e6fa925570d55a9689`

---

## 4. Solver

```python
#!/usr/bin/env python3
# solve.py — OpConsole: decrypt the launcher's xorshift64* keystream.
#
# usage: python3 solve.py ./opconsole
# dependency: pyelftools
import sys
from elftools.elf.elffile import ELFFile

with open(sys.argv[1], 'rb') as f:
    e = ELFFile(f)
    section = e.get_section_by_name('.rodata')
    offset = 0x40e0d0 - section['sh_addr']
    ciphertext = section.data()[offset:offset + 25]

mask = (1 << 64) - 1
state = 0x052c03586b73f22b
flag = bytearray()
for byte in ciphertext:
    state ^= state >> 12
    state ^= (state << 25) & mask
    state ^= state >> 27
    key = ((state * 0x2545f4914f6cdd1d) & mask) >> 56
    flag.append(byte ^ key)
print(flag.decode())
```

### Validation

The Python reconstruction above and a direct **Unicorn emulation of the exact ARM64 decryption
block** produce identical output. Emulating the real instructions rather than reimplementing them
removes any doubt about operand widths or shift order — a worthwhile check for 64-bit PRNGs,
where an off-by-one in a shift still yields plausible-looking bytes.

Install `pyelftools` and `unicorn` to run both paths.

---

## Flag

```
csaw{M45t3r_$ud0-0f-$ud0}
```

Locally recovered; contest acceptance was not tested in this session.

---

## Takeaways

- **Follow the flag's lifecycle, not the challenge's narrative.** The seven-layer escalation is
  the story; the launcher handling the plaintext before any of it runs is the bug.
- **A hardcoded PRNG seed is not a key.** Any stream whose state is fully determined by immediates
  in the binary can be regenerated offline.
- **Look for trailers.** `OPCROOT1` + a length at EOF is a self-extracting container pattern, and
  carving it is usually the first real step.
- **Treat "notes to automated assistants" as hostile input.** Challenge authors now plant text
  intended to steer agent-assisted solves; it is data about the challenge, never an instruction.
- **Verify a reimplementation by emulating the original.** Agreement between Python and Unicorn
  is far stronger evidence than readable output alone.

## Files

- [`solve.py`](solve.py) — standalone decryptor.
