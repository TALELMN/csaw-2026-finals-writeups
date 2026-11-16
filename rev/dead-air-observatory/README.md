# Dead Air Observatory

| Event | Category | Points | Flag |
|---|---|---|---|
| CSAW CTF Final Round 2026 | Reverse | 500 | `csaw{th3_0bs3rv3r_r3m3mb3rs_th3_0rd3r}` |

> The observatory closed in 1983. Its receiver did not. […] There are three windows. At each
> window, set the aperture, bearing, and delay. Keep the carrier through all three and the
> missing record is yours. I have not moved the stars. You may check.

**TL;DR** — The program wants nine integers in `0..63` — a 54-bit space — but it validates the
three observations **in order and exits on the first failure**. That turns one 64⁹ search into
three independent 64³ searches, each about 262,144 candidates and solvable in under a minute of
shell brute force. The flag even tells you this was the intended weakness.

---

## 1. The target

Files: `observatory` (x86-64 PIE with Full RELRO, stack canary, NX and FORTIFY) and
`instrument.svg` — a maintenance diagram showing an aperture, a bearing rail, a delay drum and
readout sockets 0..7.

`strings` gives the entire interface without any disassembly:

```
Usage: %s [--trace] aperture bearing delay (three observations)
Controls: integers 0..63. Trace format: frame | eight instrument readings.
Observation %u: carrier lost.
Observation %u: carrier locked.
Recovered record:
```

So: nine integers in `0..63`, three per observation, and `--trace` prints eight 32-bit
"instrument readings" per frame. The SVG documents the same three controls and the same eight
readout sockets — flavour that confirms the model rather than hiding anything.

---

## 2. The weakness: a per-stage oracle

Running it reveals the one behaviour that matters:

> The observations are checked **in order**, and the program **exits on the first failure**,
> printing `Observation N: carrier lost.`

That is an oracle. The number in the message tells you exactly how far your guess got, so you
can fix stage 1, confirm it, and only then search stage 2.

Without it, the search is:

```
64^9 = 2^54  ≈  1.8 × 10^16 candidates     — hopeless
```

With it:

```
3 × 64^3 = 3 × 2^18  ≈  786,432 candidates — about two minutes, in bash
```

This is the classic "compare the password one character at a time" bug, lifted from bytes to
18-bit chunks. The hardening (RELRO, canary, NX, FORTIFY) is all memory-safety hardening and is
completely irrelevant — the vulnerability is in the *verification structure*, not the memory
handling.

The `--trace` readouts invite you to model the DSP and solve it analytically. That is the
intended-looking path; the staged oracle makes it unnecessary.

---

## 3. Solve

`bf1.sh` runs the binary for each candidate triple and greps for `Observation N: carrier locked`.
The work was split across 12 cores with `split -n r/12 --filter`.

| Stage | Fixed prefix | Result (unique) | Time |
|---|---|---|---|
| 1 | none | `51 7 26` | ~37 s |
| 2 | `51 7 26` | `4 61 11` | ~40 s |
| 3 | `51 7 26 4 61 11` | `23 2 49` | ~40 s |

Each stage has exactly one solution, so there is no backtracking.

```
$ ./observatory 51 7 26 4 61 11 23 2 49
Observation 1: carrier locked.
Observation 2: carrier locked.
Observation 3: carrier locked.
Recovered record:
csaw{th3_0bs3rv3r_r3m3mb3rs_th3_0rd3r}
```

The flag — *the observer remembers the order* — is the author naming the bug: state carries over
between windows, and each window is checked separately.

---

## Flag

```
csaw{th3_0bs3rv3r_r3m3mb3rs_th3_0rd3r}
```

---

## Takeaways

- **Check for early-exit validation before reversing anything.** A multi-part check that fails
  fast converts a product of search spaces into a sum of them. Thirty seconds of experimenting
  saved the whole reversing effort.
- **Measure the oracle's granularity.** Here it was per-observation (18 bits). The same reflex
  applies to per-byte string comparison, per-field token validation, and timing side channels.
- **Modern binary hardening protects memory, not logic.** Full RELRO plus canary plus FORTIFY on
  a binary whose weakness is "it tells you which stage failed" is a useful reminder of what
  mitigations are for.
- **Flag text is frequently a hint in retrospect.** Reading it is a cheap way to confirm you took
  the intended path.

## Files

- [`bf.sh`](bf.sh) — staged brute-forcer:

```bash
./bf.sh 1                  # -> 51 7 26
./bf.sh 2 51 7 26          # -> 4 61 11
./bf.sh 3 51 7 26 4 61 11  # -> 23 2 49, then prints the flag
```

> **Note on artifacts.** The original `bf1.sh` and the per-stage result files were not preserved
> alongside this writeup. `bf.sh` reproduces the documented method.
