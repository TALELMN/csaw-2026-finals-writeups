# Bombe

| Event | Category | Points | Flag |
|---|---|---|---|
| CSAW CTF Final Round 2026 | Reverse | 500 | `CSAW{WE_BRING_THE_BOOMBE_BIG_FUN_CONFERENCE}` |

> My [friend] handed me this binary alongside this ciphertext `ICGR{LZ_VGUWS_CLL_PAMCLQ_WYI_HQB_KAZQPBPGNL}`
> Flag in this challenge is uppercase CSAW, but not case sensitive either way.

**TL;DR** — A homemade Enigma in an unstripped ELF. Because it has a reflector it is an
involution, so decryption is just encryption with the right settings. The key space is about
2.2 million, the ciphertext begins with `ICGR` and the plaintext must begin with `CSAW`, so a
four-letter crib plus one second of brute force finds the settings.

---

## 1. The binary

`enigma.elf`, x86-64 PIE, **not stripped**. It asks for three rotors (`I`–`V`), three offsets
(`0`–`25`) and a line of text, then runs the text through its own Enigma.

Because the symbols survive, the design reads straight out of the symbol table:
`ROTOR1..5`, `ROTORS`, `rotate_rotor`, `map_forward`, `map_inverse`, `reflector`, `roman_int`.

Reversing `main` and its helpers in radare2:

| Component | Behaviour |
|---|---|
| `roman_int` | Converts `I`..`V` to an index 0..4 into `ROTORS[]`, which points at `ROTOR1..5`. |
| Rotor | 26 `(in, out)` byte pairs. The wirings are visible in `strings`, e.g. `AYBACZDD…`. |
| `map_forward` / `map_inverse` | Look a letter up by its `in` byte, or by its `out` byte. |
| `rotate_rotor` | Rotates the `out` column left by one position. |
| `reflector` | `155 - c` — i.e. Atbash, `A↔Z`. |
| Offsets | Each rotor is rotated `offset` times before encryption starts. |
| Stepping | Rotor 1 steps after every letter. Rotor 2 steps every 8 letters (`count & 7 == 0`). Rotor 3 never steps. |
| Non-letters | Passed through unchanged, and they do **not** advance the rotors. |
| Plugboard | None. |

Signal path:

```
fwd(R1) → fwd(R2) → fwd(R3) → reflector → inv(R3) → inv(R2) → inv(R1)
```

---

## 2. Why no decrypt routine is needed

The reflector makes the whole transform an involution: it maps each letter to another and never
to itself, and running a letter through the chain twice under identical rotor state returns the
original. The rotor stepping depends only on how many *letters* have been processed, which is
identical for ciphertext and plaintext of the same length.

**Therefore `E(E(x)) = x` under the same settings** — feeding the ciphertext back into the
binary with the correct rotors and offsets decrypts it. The challenge is only to find those
settings.

(This is the same property the historical Enigma had, and the same one that made cribs so
devastating against it: a letter never encrypts to itself.)

---

## 3. Brute force with a crib

The key space is tiny:

```
5³ rotor choices (repeats allowed)  ×  26³ offsets  ≈  2.2 million
```

`bf.c` reimplements the machine using the rotor tables read straight out of the ELF (`rotors.h`,
file offset `0x3020`, stride 64), keeps every setting that maps the first four ciphertext
letters `ICGR` to `CSAW`, and decrypts the full ciphertext for each survivor. **The search takes
about one second.**

About **100** settings satisfy the four-letter crib — which is roughly what you would expect
(2.2M / 26⁴ ≈ 5, inflated by the rotor structure). Exactly one produces English:

```
IV II V | 15 4 24 | CSAW{WE_BRING_THE_BOOMBE_BIG_FUN_CONFERENCE}
```

Verified against the real binary:

```
$ printf 'IV II V\n15 4 24\nICGR{LZ_VGUWS_CLL_PAMCLQ_WYI_HQB_KAZQPBPGNL}\n' | ./enigma.elf
CSAW{WE_BRING_THE_BOOMBE_BIG_FUN_CONFERENCE}
```

A four-letter crib narrows 2.2M to ~100; readability picks the one. The challenge name is the
hint — this is exactly what a Bombe did, mechanically.

---

## Flag

```
CSAW{WE_BRING_THE_BOOMBE_BIG_FUN_CONFERENCE}
```

---

## Takeaways

- **A reflector buys you free decryption and costs the designer everything.** Self-inverse
  ciphers let an attacker reuse the encryption oracle unchanged.
- **Known-plaintext is almost always available in CTF.** `csaw{` / `CSAW{` is a five-character
  crib handed to you on every single challenge.
- **Extract tables, do not retype them.** Reading `ROTOR1..5` out of the ELF at a fixed offset
  and stride removes a whole class of transcription bugs, and keeps the reimplementation honest.
- **Verify against the original binary.** A reimplementation that agrees with the real program on
  the real input is proof; one that merely produces readable text is a hypothesis.

## Files

- `rotors.h` — rotor tables extracted from the binary.
- `bf.c` — brute-forcer (`gcc -O2 -o bf bf.c && ./bf`).
- `flag.txt`

> **Note on artifacts.** The original `solve/` sources were not preserved alongside this writeup.
> Everything needed to rebuild them is above: the table location (`0x3020`, stride 64), the
> stepping rules, and the signal path.

## Tools

radare2, `strings`, a C brute-forcer.
