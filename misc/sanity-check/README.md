# Sanity Check

| Event | Category | Difficulty | Points | Flag |
|---|---|---|---|---|
| CSAW CTF Final Round 2026 | Misc | Easy | 500 | `csaw{W3LC0ME2CSAW!}` |

> The truth was spoken aloud, in pieces, in every room. The last piece sits where the law of the
> house is written.

**TL;DR** — The flag is split into hex fragments posted across the CTF Discord's channels. The
rules channel contains a `test_flag` message that looks like the answer but is only a checksum —
the genuine last piece is the out-of-place number **21** in "Please do not ask for 21 hints",
which is hex for `!`.

---

## 1. Collect the fragments

"In every room" means every channel; "where the law of the house is written" means `#rules`.
Each channel holds one hex fragment, read in server channel order:

| Channel | Hex | Text |
|---|---|---|
| general | `57 33 4c` | `W3L` |
| memes | `43 30 4d` | `C0M` |
| recruitment | `45 32 43` | `E2C` |
| networking | `53 41` | `SA` |
| fun | `57` | `W` |

---

## 2. Why the obvious answer is rejected

The rules channel also carries a `test_flag` message containing the same hex joined together:
`W3LC0ME2CSAW`. Wrapping that in `csaw{}` is rejected.

That rejection is informative rather than discouraging. If `test_flag` reproduces exactly what
you already assembled, it is a **checksum confirming your fragments are correct and in the right
order** — which means the thing still missing is not among them. The real last piece is
elsewhere in the rules.

---

## 3. The last piece

The rules text reads:

> "Please do not ask for **21** hints"

The number is out of place — no rules message naturally specifies twenty-one. Read as hex, `21`
is `!`, which completes a sentence that otherwise ends mid-word:

```
W3LC0ME2CSAW  +  !   ->   W3LC0ME2CSAW!
```

---

## 4. Solver

```python
#!/usr/bin/env python3
# solve.py — Sanity Check: reassemble the Discord hex fragments.
FRAGMENTS = [               # in server channel order
    ("general",     "57 33 4c"),
    ("memes",       "43 30 4d"),
    ("recruitment", "45 32 43"),
    ("networking",  "53 41"),
    ("fun",         "57"),
]
RULES_HINT = "21"           # from "ask for 21 hints" in the rules message


def hex_to_text(h: str) -> str:
    return bytes.fromhex(h.replace(" ", "")).decode()


body = "".join(hex_to_text(h) for _, h in FRAGMENTS) + hex_to_text(RULES_HINT)
print(f"csaw{{{body}}}")
```

```
csaw{W3LC0ME2CSAW!}
```

---

## Flag

```
csaw{W3LC0ME2CSAW!}
```

---

## Takeaways

- **A rejected submission is data.** `test_flag` matching your assembly exactly meant the
  fragments were right and something else was missing — a far more useful conclusion than
  "my decoding is broken".
- **Encoding consistency carries through.** Once the puzzle establishes "numbers in this
  challenge are hex", every stray number is a candidate — including one embedded in an English
  sentence.
- **Read the prose clue literally.** "Every room" (every channel) and "where the law of the house
  is written" (`#rules`) each name a precise location.

**Original writeup credit:** 3angour.
