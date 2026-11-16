# Misc

| Challenge | Bug class | Flag |
|---|---|---|
| [Processing all of That](processing-all-of-that/) | An inescapable tool whitelist; `top`'s author-controlled Inspect (`Y`) entries read per-PID files | `csaw{st1ll_0p3n_0n_thr33}` |
| [Manual Override](manual-override/) | Three concurrent sessions race a payout sleep; then `in <tick>` turns a latency puzzle into arithmetic | `csaw{r1p_b10w4r3_m455_3ff3c7_15_7h3_b357_64m3_0f_4ll_71m3!}` |
| [Robots Lately](robots-lately/) | ROS 2 bag killed mid-flush: 21 messages, including the crash dump, live only in the SQLite WAL | `csaw{v4cuum_d03snt_m34n_g0n3}` |
| [Lost in Embedding](lost-in-embedding/) | Embedding inversion: coordinate ascent on cosine similarity against a pinned public encoder | `csaw{d0_0r_d0_n0t_th3r3_1s_n0_try-edd03123cf9f06b9}` |
| [Sanity Check](sanity-check/) | Hex fragments posted across the CTF Discord's channels | `csaw{W3LC0ME2CSAW!}` |

**Recurring theme:** the answer always lives in something nobody thinks of as an attack surface —
a monitoring tool's inspect menu, an undocumented command argument, a database's write-ahead log,
or the leftover vector of a "deleted" record.
