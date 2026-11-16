# Manual Override

| Event | Category | Difficulty | Flag |
|---|---|---|---|
| CSAW CTF Finals 2026 | Misc | Hard | `csaw{r1p_b10w4r3_m455_3ff3c7_15_7h3_b357_64m3_0f_4ll_71m3!}` |

**TL;DR** — A *Mass Effect*-themed 80×24 ANSI terminal game over raw TCP. Two halves:
first, a **three-session race condition** on every crate that triple-claims each payout, laundered
through omni-gel to reach exactly the 45,000 credits needed for clearance; then a **timed
four-ring puzzle** that becomes deterministic once you notice the `in` command accepts the SYNC
tick as an argument, which removes network latency from the equation entirely.

---

## Part 1 — the economy

Key observations:

- `new` requires a proof of work: a decimal suffix such that `sha256(prefix + suffix)` begins
  with 23 zero bits. `login <id> <pin>` requires none — so make accounts sparingly and reuse them.
- An account permits **three concurrent sessions**, and that cap cannot be raced.
- `bypass <n>` opens a wire-tracing board (9 pairs, ~10 s), different per session. **The payout
  scanner sleeps ~1.5 s after the board is completed.**

### The race

That 1.5-second sleep is the bug. If all three sessions submit their final pair at the same
instant:

- **one** session gets `BYPASS COMPLETE` → **+1,500 real credits**
- the other two each get a `DOUBLE-CLAIM` → **+1,500 *mission* credits** each

Over 12 crates: **18,000 real + 36,000 mission**.

### Laundering mission credits

Mission credits evaporate on the shuttle — but **omni-gel does not**. Convert before travelling:

```
buy gel 360      (in the Yard — spends the 36,000 mission credits)
travel afterlife
sell gel 360     (at 75 cr each)            -> +27,000 real
```

```
18,000 + 27,000 = 45,000      — exactly the price of `buy clearance`
```

The arithmetic landing exactly on the target is the confirmation that this is the intended path.
It also means there is **nothing left over** for the 25-gel override reset — so the ring puzzle
is effectively **one attempt per account**.

---

## Part 2 — the ring puzzle

`decrypt` shows four concentric rings. Each has one gap moving at a constant speed (random per
attempt) and there is a 25-second timer. A ring passes only when its gap sits in the exact cell
under the `▼` marker — column 33 of that ring's top row.

### Why blind timing is hopeless

A bare `in` is evaluated after a "handshake" delay that is **bimodal**: roughly 3–7 **or** 18–23
ticks (the SYNC counter runs at 60 ticks/s), with nothing on screen predicting which. Against a
tolerance of about one cell, that is unplayable.

### The actual mechanism

The UI prints a hex `SYNC` counter, and every failure quotes one:

```
Ring 1 sealed (sync 00fa)
```

Sending `in <tick>` for a tick that had not happened yet returned:

```
omni-tool: sync from the future rejected
```

— **and cost no penalty**. Two facts fall out of that one probe:

1. `in` takes a tick argument.
2. The server checks the ring's position **at that tick**, not at arrival time.

That removes network latency from the problem completely. You are no longer trying to arrive at
the right moment; you are *naming* the moment.

### Solving each ring

Per ring: render frames with `pyte`, fit the gap's perimeter position against SYNC (constant
velocity), solve for the tick at which the gap sits under the marker, and send `in <4-hex-digit
tick>` timed to arrive a few ticks later.

> **Refit on every frame until just before sending.** Fitting once and extrapolating ~110 ticks
> ahead missed ring 2 by a single cell on the first live attempt — and with one attempt per
> account, that is the whole run.

Once all four rings pass, the datapad decrypts and prints the clearance code.

---

## Reproduce

The solve is split across four scripts:

| Script | Role |
|---|---|
| `tui.py` | pyte TCP client |
| `race.py` | wire-tracer `solve()` |
| `fullx.py` | account → 12-crate race → gel laundering → `buy clearance` |
| `t2.py` | the ring solver |

With the host set in `tui.py` and `pyte`/`numpy` installed (~3 minutes end to end):

```bash
STAGE=t2.py PYTHONIOENCODING=utf-8 python fullx.py
```

Winning ring log from the live solve:

```
SEND b'in 007e' ring 1  -> Ring 1 breached (sync 007e)
SEND b'in 0115' ring 2  -> Ring 2 breached (sync 0115)
SEND b'in 01ab' ring 3  -> Ring 3 breached (sync 01ab)
SEND b'in 01dd' ring 4  -> Final ring breached.
                           Datapad cipher broken. Extracting clearance...
                           CLEARANCE CODE: csaw{...}
```

---

## Flag

```
csaw{r1p_b10w4r3_m455_3ff3c7_15_7h3_b357_64m3_0f_4ll_71m3!}
```

---

## Takeaways

- **A sleep between "task complete" and "payout recorded" is a race window.** Three concurrent
  sessions finishing simultaneously is enough; no timing precision is needed beyond "together".
- **Follow which currencies survive which transitions.** Mission credits were worthless on their
  own and became 27,000 real credits once converted into an item that travels.
- **Probe the command grammar for undocumented arguments.** `in <tick>` was never documented; one
  rejected-but-free probe revealed both that the argument exists and that the server evaluates
  the *named* tick rather than arrival time — converting a latency race into arithmetic.
- **Rejections that cost nothing are free experiments.** Finding the no-penalty error path made
  the discovery safe to make.
- **Refit right up to the moment you commit.** Extrapolating a linear model over a hundred ticks
  accumulates exactly the error that a one-cell tolerance will not forgive.
- **When the economy balances exactly to the target price, you have found the intended path** —
  and also lost your margin for error.

> **Note on artifacts.** The four solver scripts were not preserved alongside this writeup. The
> mechanisms, the exact economy arithmetic and the winning tick sequence are documented above.
