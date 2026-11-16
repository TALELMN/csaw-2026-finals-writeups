# Web

Six web challenges, spanning server-side template injection, reverse-proxy header trust,
prototype pollution, integer overflow and a long multi-stage proxy chain.

| Challenge | Bug class | Flag |
|---|---|---|
| [Joshua](joshua/) | Prototype pollution → RCE, then a forged auth token because the MAC does not cover the role byte | `csaw{pr0t0_p0llut3d_my_w4y_2_a_f0rg3d_4dm1n_t0k3n}` |
| [Tempaude](tempaude/) | Ruby mustache 1.1.2 SSTI → arbitrary file read via a mutable global and `String#replace` | `csaw{mu5t4che_do3s_uhhhhh}` |
| [Golf Heist](golf-heist/) | Caddy `forward_auth` + `copy_headers` does not strip client headers (GHSA-7r4p-vjf4-gxv4) | `csaw{REDACTED}` |
| [Low Tide](low-tide/) | Five-stage SCADA proxy chain; only one of four load-balanced workers serves the relay | `csaw{REDACTED}` |
| [CSALE](csale/) | Account enumeration + unrate-limited 4-digit PIN, plus a two-layer decoy flag | `csawctf{REDACTED}` |
| [CSALE Revenge](csale-revenge/) | Signed 32-bit integer overflow in the checkout total | `csawctf{REDACTED}` |

**Recurring theme:** every one of these is a trust boundary drawn in the wrong place — a template
engine trusting its own method table, a proxy trusting a client header, a backend trusting a
derived integer, a merge function trusting a key name.

> The four `REDACTED` flags were published that way originally and no local copy of the real
> values survives; see the [repository notes](../README.md#notes-on-accuracy).
