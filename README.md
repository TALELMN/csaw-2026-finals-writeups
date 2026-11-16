# CSAW CTF 2026 — Finals Writeups

Writeups for the **CSAW CTF Final Round 2026**, organised by category. Each challenge has its own
directory containing a full writeup and, where one exists, a runnable solver.

Every writeup follows the same shape: challenge metadata and a one-paragraph **TL;DR**, then
recon, then the vulnerability *and why it works*, then exploitation, then the solver, the flag
with a note on where it came from, and the takeaways worth keeping.

**26 challenges** across 7 categories.

---

## Contents

### [Web](web/) — 6

| Challenge | Bug class | Flag |
|---|---|---|
| [Joshua](web/joshua/) | Prototype pollution → RCE → forged auth token (MAC does not cover the role byte) | `csaw{pr0t0_p0llut3d_my_w4y_2_a_f0rg3d_4dm1n_t0k3n}` |
| [Tempaude](web/tempaude/) | Ruby mustache 1.1.2 SSTI → arbitrary file read via `String#replace` | `csaw{mu5t4che_do3s_uhhhhh}` |
| [Golf Heist](web/golf-heist/) | Caddy `forward_auth` header injection (GHSA-7r4p-vjf4-gxv4) | `csaw{REDACTED}` |
| [Low Tide](web/low-tide/) | Five-stage SCADA proxy chain behind a load balancer | `csaw{REDACTED}` |
| [CSALE](web/csale/) | Account enumeration + unrate-limited PIN brute force + a two-layer decoy | `csawctf{REDACTED}` |
| [CSALE Revenge](web/csale-revenge/) | Signed 32-bit integer overflow in checkout | `csawctf{REDACTED}` |

### [Crypto](crypto/) — 3

| Challenge | Bug class | Flag |
|---|---|---|
| [Beeseal](crypto/beeseal/) | ECDSA biased nonces → Hidden Number Problem lattice attack | `csaw{b33swellUNS34LED_}` |
| [Aircrypt](crypto/aircrypt/) | µTESLA TOCTOU: frame accepted after its key is disclosed | `csaw{t0ct0u_on_m1cr0tesla_1s_wh4t_fl1es_the_gh0st-…}` |
| [dumb](crypto/dumb/) | XOR-shared RSA public keys; PEM headers leak subset parity | `csaw{1_th1nk_1m_d4mb_m4yb3_j4st_h4ppy}` |

### [Reverse Engineering](rev/) — 3

| Challenge | Bug class | Flag |
|---|---|---|
| [Bombe](rev/bombe/) | Homemade Enigma; reflector makes it an involution, crib + brute force | `CSAW{WE_BRING_THE_BOOMBE_BIG_FUN_CONFERENCE}` |
| [Dead Air Observatory](rev/dead-air-observatory/) | Staged validation turns one 64⁹ search into three 64³ searches | `csaw{th3_0bs3rv3r_r3m3mb3rs_th3_0rd3r}` |
| [OpConsole](rev/opconsole/) | Launcher decrypts the flag (xorshift64\*) before the daemon ever runs | `csaw{M45t3r_$ud0-0f-$ud0}` |

### [Jails & Sandbox Escapes](jail/) — 4

| Challenge | Bug class | Flag |
|---|---|---|
| [Hell Jail](jail/hell-jail/) | Anti-debug shows a decoy seccomp filter; real one allows `openat` on a magic `mode` | `csaw{uNC0v3rd_t#e_Dev1l$_0rDe&l__…}` |
| [NodeOS](jail/nodeos/) | Prototype pollution injects an entry into the permission table | `csaw{cust0m1z3_w3nt_4ll_th3_w4y_up}` |
| [NodeOS 2](jail/nodeos-2/) | `Error.prepareStackTrace` VM escape → `Module._load` → `dlopen` privesc | `csaw{l04d3d_th3_dr1v3r_g0t_th3_k3ys}` |
| [Sumi Jail](jail/sumi-jail/) | Echoed deposits leak the randomised opcode mapping; flag read from `/proc/<pid>/fd/3` | `csaw{bu1lt_th3_wh0l3_c0mm4nd_by_h4nd}` |

### [Forensics & Steganography](forensics/) — 3

| Challenge | Bug class | Flag |
|---|---|---|
| [Into The Vault You Break](forensics/into-the-vault-you-break/) | 3-bit LSB PNG → zip → pcap → encrypted zip → spoken base64 | `csaw{but_th3r3_1s_n0th1ng_y0u_c@n_t@k3}` |
| [You Can't Steal My Stuff](forensics/you-cant-steal-my-stuff/) | Reversed speech + WAV metadata + Vigenère-over-base64 | `csaw{but_y0u_c@nt_st3@l_my_h3@rt}` |
| [Music Security Department 2](forensics/music-security-department-2/) | Stereo-difference spectrogram + melody-as-hex + 300-baud FSK | `csaw{music-is-my-favorite-love-language}` |

### [Misc](misc/) — 5

| Challenge | Bug class | Flag |
|---|---|---|
| [Processing all of That](misc/processing-all-of-that/) | `top`'s author-controlled Inspect (`Y`) entries read per-PID files | `csaw{st1ll_0p3n_0n_thr33}` |
| [Manual Override](misc/manual-override/) | Three-session payout race, then `in <tick>` defeats a timing puzzle | `csaw{r1p_b10w4r3_m455_3ff3c7_15_7h3_b357_64m3_0f_4ll_71m3!}` |
| [Robots Lately](misc/robots-lately/) | ROS 2 bag: 21 messages recovered from the SQLite WAL | `csaw{v4cuum_d03snt_m34n_g0n3}` |
| [Lost in Embedding](misc/lost-in-embedding/) | Embedding inversion by coordinate ascent on cosine similarity | `csaw{d0_0r_d0_n0t_th3r3_1s_n0_try-…}` |
| [Sanity Check](misc/sanity-check/) | Hex fragments across Discord channels | `csaw{W3LC0ME2CSAW!}` |

### [OSINT](osint/) — 2

| Challenge | Bug class | Flag |
|---|---|---|
| [The Final Gateway](osint/the-final-gateway/) | Photo geolocation, EXIF/XMP clues, SIFT verification | `CSAW{BANNERMAN_CASTLE}` *(proposed)* |
| [Pokémon Talk](osint/pokemon-talk/) | Repeating-key XOR hint → exact-phrase Reddit search | `CSAW{p0k3m0n_talk}` |

---

## Notes on accuracy

These writeups try to be honest about what was proven and what was inferred:

- **Redacted flags.** Four web challenges (CSALE, CSALE Revenge, Golf Heist, Low Tide) were
  originally published with their flags redacted and no local copy of the real values survives.
  They are kept as `REDACTED` rather than invented. Every other flag is the real value.
- **Unverified submissions.** Where a flag was recovered locally but never accepted by the
  scoreboard, the writeup says so explicitly — see *You Can't Steal My Stuff*,
  *Music Security Department 2*, *OpConsole* and *The Final Gateway*.
- **Proposed answers.** *The Final Gateway* reaches its destination by inference; the photo match
  is proven, the flag spelling is not.
- **Inferred server code.** Where a challenge's source was never available, reconstructed code is
  labelled as inferred from behaviour — most notably in *NodeOS*.
- **Reconstructed artifacts.** A few challenges' original solver scripts were not preserved. Those
  writeups document the method in full and say so; where a faithful reimplementation was possible
  it is included and marked as a reconstruction.

## Repository layout

```
<category>/<challenge>/
    README.md      the writeup
    solve.py       the solver, where one exists
    …              challenge sources and artifacts referenced by the writeup
```

Each category directory also has its own index.

## Running the solvers

Most are standalone Python 3 scripts. Dependencies, where any, are listed in each writeup — the
common ones are `requests`, `numpy`, `scipy`, `pyte`, `websocket-client`, `pillow` and `fpylll`.
Live-service solvers expect the challenge instance to be reachable, which for the finals meant
the CTF WireGuard VPN.
