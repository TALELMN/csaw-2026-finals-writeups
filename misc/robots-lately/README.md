# Robots Lately

| Event | Category | Flag |
|---|---|---|
| CSAW CTF Finals 2026 | Misc / Forensics | `csaw{v4cuum_d03snt_m34n_g0n3}` |

> We recovered a field test recording from an autonomous ground vehicle. The operator says a crash
> dump was encrypted under "the safety subsystem's rolling session key." We need that dump.

**TL;DR** — A ROS 2 bag whose recorder was killed before the storage flush completed. 21 messages
— including the crash dump itself — exist only in the SQLite **write-ahead log**, not the main
database. Recover them, decode the CDR messages, and derive a rolling HMAC key chain over all
**284** status contributions. Using only the 264 committed ones yields a different key and
garbage, so the WAL recovery is mandatory. The flag says it: *vacuum doesn't mean gone*.

---

## 1. The files

`robots-lately.tar` contains a ROS 2 Humble bag and its workspace:

- `field_test.db3` and `field_test.db3-wal` — the SQLite bag plus its write-ahead log
- `metadata.yaml`, `dds_config.xml`, `incident_report.txt`
- two packages with message definitions: `agv_diagnostics` (`InternalStatus`,
  `DiagnosticPayload`, `SessionInfo`) and `agv_safety` (`CrashDump`)

`incident_report.txt` states the recorder was killed before the storage flush completed — the
single most important sentence in the handout.

---

## 2. Recovering the uncheckpointed rows

`field_test.db3` on its own holds **811** messages. `metadata.yaml` disagrees with *itself*:
811 at the top level, **832** under `files[]`. That 21-message discrepancy is the whole first
stage, and it is visible without opening a single binary.

The missing 21 are sitting in the WAL:

- 20 `/diagnostics/internal` messages, `sequence_number` 264–283
- the single `/diagnostics/crash_dump` message

SQLite's WAL holds committed pages that have not yet been checkpointed back into the main
database file. They are not lost, merely not merged — so opening a **copy** of the database
*together with* its `-wal` file (or checkpointing that copy) yields all 832 rows.

`solve_robots.py` goes further and parses the WAL frames and b-tree leaf pages by hand, so
nothing can be silently discarded by a checkpoint.

> **Always copy before touching a WAL.** Opening the original with a client that checkpoints and
> then truncates can destroy exactly the evidence you came for.

---

## 3. Decoding the messages

Messages are CDR-encoded. The fields that matter:

```
CrashDump:        crash_time, node_name, crash_code,
                  uint8[32] encrypted_payload, uint8[16] iv

InternalStatus:   sequence_number, uint8[16] node_nonce, metric_values,
                  epoch, uint8[32] contribution, auth_tag
```

Recovered crash dump:

```
payload  05f91d48965303c08b79a9a1a5e941ffee4dfe5fd89a8daf77c3fc839cdb4d71
iv       c8f9b4a73e5a2f9de6c2c9bcf1c64404
```

There are **284** `InternalStatus` messages, sequence numbers 0–283 with no gaps, all in epoch 1.
No gaps is the confirmation that the WAL recovery was complete.

---

## 4. Why the key material is in the bag at all

`dds_config.xml` installs a content filter on `/diagnostics/internal` with the expression
`severity > 3`.

`InternalStatus` **has no `severity` field** — the field is called `level`. So the filter never
matches anything, nothing is filtered out, and **every contribution was recorded**. A
misconfigured DDS content filter is the reason the key material is sitting in an evidence bag.

The same file also holds the shared secret:

```
e47b0c1a9f3d58267e1094bfa2c36d8503e7f14b6a928dc5073ef189b4560a2d
```

and the DDS participant name `agv_field_test_04`.

---

## 5. The rolling session key

```
K0      = HMAC-SHA256(shared_secret, "agv_field_test_04")
K(i+1)  = HMAC-SHA256(K(i), contribution_i)        for i = 0..283, in sequence_number order
plaintext = AES-256-CBC-decrypt(key = K284, iv = CrashDump.iv, CrashDump.encrypted_payload)
```

This is a hash chain, so it is all-or-nothing: **every** contribution must be present, in order.
Values:

```
K0   = 625fff69ada46ea7f46ae4653f4bed5c3e1f19372622fe50bf52d9eead16591e
K284 = 1859ff09ad781688356a5e2c6301710f2d076123c0b298d2b188de8e3c14caf2
```

The plaintext is `csaw{v4cuum_d03snt_m34n_g0n3}` followed by three bytes of valid PKCS#7 padding
— the padding validating is itself a check that the key is right.

Using only the 264 committed contributions produces a completely different `K264` and
unintelligible output, with no partial credit and no near-miss to hint that you were close. The
WAL recovery is not optional.

---

## 6. Reproduce

```bash
python solve_robots.py <dir containing field_test.db3 and field_test.db3-wal>
```

It performs the WAL recovery and CDR decoding. The key chain and decryption above were re-run
against the extracted messages and reproduce the flag.

---

## Flag

```
csaw{v4cuum_d03snt_m34n_g0n3}
```

---

## Takeaways

- **A database file is not the database.** SQLite's `-wal` sidecar holds committed data the main
  file has never seen. In forensics, always take the WAL (and `-shm`), always work on a copy, and
  never let a tool checkpoint the original.
- **Metadata that disagrees with itself is the lead.** `metadata.yaml` saying both 811 and 832
  pointed straight at 21 missing rows before any binary parsing began.
- **Misconfiguration is the plot.** The DDS filter referenced a field name that does not exist
  (`severity` vs `level`), so it silently matched nothing and recorded everything — a realistic
  bug and the reason the evidence exists.
- **Hash chains are all-or-nothing.** There is no graceful degradation from a missing link, which
  makes "almost complete" recovery indistinguishable from total failure.
- **Validate with the padding.** Correct PKCS#7 padding after decryption is cheap confirmation
  that the derived key is right.

## Files

- `solve_robots.py` — WAL frame and b-tree leaf parsing, CDR decoding, key chain, decryption.

> **Note on artifacts.** The original solver was not preserved alongside this writeup. The
> recovery procedure, message layouts, both chain endpoints and the ciphertext/IV are given in
> full above so each stage can be verified independently.
