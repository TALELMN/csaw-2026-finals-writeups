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
