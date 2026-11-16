# Reverse Engineering

| Challenge | Bug class | Flag |
|---|---|---|
| [Bombe](bombe/) | Homemade Enigma; the reflector makes it an involution, so a 4-letter crib plus a 2.2M brute force wins | `CSAW{WE_BRING_THE_BOOMBE_BIG_FUN_CONFERENCE}` |
| [Dead Air Observatory](dead-air-observatory/) | Observations validated in order with early exit: one 64⁹ search becomes three 64³ searches | `csaw{th3_0bs3rv3r_r3m3mb3rs_th3_0rd3r}` |
| [OpConsole](opconsole/) | The launcher decrypts the flag with a hardcoded xorshift64\* keystream before the daemon ever starts | `csaw{M45t3r_$ud0-0f-$ud0}` |

**Recurring theme:** in all three, understanding the *structure* mattered far more than reading
the code. A reflector, an early-exit loop and a pipe write each made the bulk of the binary
irrelevant.

See also [Hell Jail](../jail/hell-jail/) — presented as a 500-point rev challenge, but filed
under [jail](../jail/) here for its seccomp and payload work.
