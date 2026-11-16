# Jails & Sandbox Escapes

| Challenge | Bug class | Flag |
|---|---|---|
| [Hell Jail](hell-jail/) | A `TracerPid` check shows debuggers a decoy seccomp filter; the real one allows `openat` when the ignored `mode` argument hashes to a magic value | `csaw{uNC0v3rd_t#e_Dev1l$_0rDe&l__$uch_&_e^v1l_M0nst3r__t#aNk$_f0r_v1s1Tng}` |
| [NodeOS](nodeos/) | `__proto__` reaches a recursive merge; injecting a correctly *shaped* entry into the permission table makes `/flag.txt` readable | `csaw{cust0m1z3_w3nt_4ll_th3_w4y_up}` |
| [NodeOS 2](nodeos-2/) | `Error.prepareStackTrace` leaks a host function → `Module._load` bypasses the allowlist → `process.dlopen` runs a `setuid(0)` constructor | `csaw{l04d3d_th3_dr1v3r_g0t_th3_k3ys}` |
| [Sumi Jail](sumi-jail/) | Echoed deposits leak the randomised opcode mapping in one probe; the real flag is read from an unlinked file via `/proc/<pid>/fd/3` | `csaw{bu1lt_th3_wh0l3_c0mm4nd_by_h4nd}` |

**Recurring themes:**

- **Removing a JS binding does not remove the underlying capability.** NodeOS 2 deleted
  `seteuid` from the JS surface while leaving `ruid = 0`; Hell Jail dropped `open` from the
  whitelist and left `openat` behind a password.
- **An unlinked file is still readable.** Sumi Jail and
  [Processing all of That](../misc/processing-all-of-that/) both hide the real flag behind a held
  file descriptor in `/proc`, with a decoy flag in the obvious place.
- **What a sandbox shows you is not what it does.** Hell Jail's filter depends on whether you are
  watching; NodeOS returns identical output for "wrong payload shape" and "impossible".
