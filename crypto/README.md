# Crypto

| Challenge | Bug class | Flag |
|---|---|---|
| [Beeseal](beeseal/) | ECDSA nonces drawn from `[1, 2^248)`; Hidden Number Problem lattice attack with corrupted-signature filtering | `csaw{b33swellUNS34LED_}` |
| [Aircrypt](aircrypt/) | µTESLA receiver accepts a frame *after* its epoch key is disclosed — a sign error on the skew margin | `csaw{t0ct0u_on_m1cr0tesla_1s_wh4t_fl1es_the_gh0st-49eb93237a6e281a}` |
| [dumb](dumb/) | XOR-shared RSA public keys; constant PEM headers leak the parity of each subset | `csaw{1_th1nk_1m_d4mb_m4yb3_j4st_h4ppy}` |

**Recurring theme:** none of the three breaks a primitive. Beeseal attacks nonce *generation*,
Aircrypt attacks a *timestamp comparison*, and dumb attacks key *distribution* — the RSA itself
is perfectly sound. The cryptography is almost never the weak part.
