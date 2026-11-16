# Into The Vault You Break

| Event | Category | Points | Flag |
|---|---|---|---|
| CSAW CTF Final Round 2026 | Forensics / Steganography | 500 (dynamic) | `csaw{but_th3r3_1s_n0th1ng_y0u_c@n_t@k3}` |

> when you break in, look around.....

**TL;DR** — Five nested layers:

```
PNG  →  (3-bit LSB)  →  zip  →  pcap (holds the password)  →  encrypted zip  →  WAV
     →  three disguised segments of spoken base64  →  flag
```

The embedding uses **three** low bits per channel, not one, so a default `zsteg`-style 1-bit scan
finds nothing. The WAV's final fraction of a second draws **312** in the spectrogram — the order
to reassemble the three speech segments in.

**Handout:** `intothevaultyoubreak.png`, 3661 × 4058 8-bit RGB, 17,697,556 bytes — a hand-painted
vault scene with a "CSAW '26" porthole.

```
SHA-256: b206e80449cb96ce67f8dc15e0aba7f9876f4f6051611f776c01e48a2eb9c145
```

---

## Layer 1 — the PNG and a 3-bit LSB payload

**Surface checks find nothing.** `exiftool`, the chunk list and `binwalk` are all clean: only
IHDR/IDAT/IEND, no text chunks, no trailing data.

**Bit planes are the tell.** In the top half of the image, bit planes 0 and 1 are uniform noise
*even across the strong black outlines*. In the bottom half, the outlines show through normally.
Paint texture does not behave that way; embedded data does.

**Measuring it turns a hunch into a number.** For each bit plane, compute the fraction of
horizontally adjacent pixels whose bit agrees:

| bit | top (rows 0–1900) | bottom (rows 2100–3950) |
|---|---|---|
| 0 | 0.5001 | 0.5818 |
| 1 | 0.5001 | 0.6818 |
| 2 | **0.5000** | 0.7993 |
| 3 | 0.8474 | 0.8874 |

Natural image data is spatially correlated, so neighbouring bits agree well above 50%. A plane
sitting at *exactly* 0.5000 is incompressible — i.e. data. Bits 0–2 are random in the top half
and bit 3 is normal, so **three LSBs per channel carry the payload**, starting at pixel 0.

The payload ends around row 1980, which matches the size:
`(4 + 8,155,550 bytes) × 8 bits ÷ 9 bits per pixel ÷ 3661 ≈ 1980 rows`.

**Bit order** was resolved by trying all 16 orderings (RGB/BGR × row/column scan × bit order ×
byte packing) and checking for a known file signature. Exactly one works:

> **row-major, channels R→G→B, bits 2→1→0 (MSB first), packed big-endian**

The resulting stream starts `9e 71 7c 00` — a little-endian u32 length, `0x007c719e` =
8,155,550 — followed by `PK\x03\x04`. Note the signature is at **offset 4, not 0**: a length
prefix is exactly the sort of thing that makes a `binwalk`-style signature scan at offset 0 come
up empty.

---

## Layer 2 — the outer zip

```
vault/vault.pcap          14,047 bytes
vault/innervault.zip   8,151,663 bytes   (encrypted; contains innervault/vault.wav)
```

---

## Layer 3 — a pcap with the password in plaintext

**The decoys:** 200 TCP ACK packets from `192.168.1.x` to `93.184.216.x` on ports 53/80/443/8080.
Every IP and TCP header field — ID, TTL, flags, seq/ack, window, urgent pointer — is *constant*,
so there is no header-field covert channel to decode. Checking which fields actually vary is a
two-minute triage that rules out the entire category.

**The key:** `tcp.len` takes two values, and exactly one packet has a payload. **Packet #121**
(`192.168.1.76:52482 → 93.184.216.20:53`), 23 bytes:

```
$ tshark -r vault.pcap -Y "tcp.len>0" -T fields -e tcp.payload | xxd -r -p
the key is vaultbreaker
```

---

## Layer 4 — the WAV: spoken base64 in three disguises

```bash
unzip -P vaultbreaker innervault.zip     # -> innervault/vault.wav
```

62 seconds of 16-bit stereo 44.1 kHz audio (61.686 s of speech plus a short tail). Both channels
show the same content in the spectrogram, though the samples are not bit-identical.

**The ordering clue.** The final ~0.37 seconds draw **312** in the spectrogram. That is the order
to concatenate the three segments — and, importantly, *not* part of the flag.

*(`solve.py` renders this as `artifacts/spectrogram-clue.png`; the three digits are
clearly legible in the 500–4000 Hz band of the tail.)*

**The three segments.** The spectrogram splits into three blocks, each a voice *spelling base64
characters* ("capital Y, 3, capital N, h, d, …"), each with a different transform applied:

| Segment | Interval | What the spectrogram shows | Correction | Base64 recovered |
|---|---|---|---|---|
| 1 | 0–22.19 s | full-band speech with harmonics ~800 Hz apart ("quacking") | pitch **down** (≈ −24 semitones / `sox pitch -2200`) | `jNfMXNfbjB0aDFuZ195` |
| 2 | 22.19–42.23 s | energy crushed below ~300 Hz, band-limited to 4 kHz | pitch **up** (≈ +24 semitones / `sox pitch +2200`) | `MHVfY0BuX3RAazN9` |
| 3 | 42.23–61.31 s | speech that only makes sense backwards | reverse the samples | `Y3Nhd3tidXRfdGgzc` |

Order **3 → 1 → 2**, exactly as the `312` clue says — and the cross-check is immediate, because
segment 3 decodes to `csaw{but_t…`.

Practical notes that cost time:

- **Pitch-correct at the original sample rate.** Downsampling segment 1 before lowering its pitch
  throws away speech information you need.
- **Transcribe manually, or prime the recogniser.** The speaker says "capital" before uppercase
  letters. Raw ASR confuses B/E, D/Z, F/S and M/N and will happily emit nonsense; faster-whisper
  `small.en` only behaved with `initial_prompt="Spelled characters: capital Y, 3, lowercase n, j, …"`.
  Without it, it hallucinates ("Thank you for watching!").
- **Segment boundaries are approximate** — all three transitions fall in pauses, so a rough cut
  is fine.

---

## Resolving the last ambiguity

Segment 2's characters were the least certain (M/N, B/V, case markers). Rather than re-listening
indefinitely, brute-force the uncertain positions: **64 printable candidates** in total. Exactly
one decodes to an English sentence:

> *"but there is nothing you can take"*

Re-encoding that flag reproduces all three heard segments character for character, apart from one
a/A case marker. A teammate independently recovered `csaw{but_th3r3_1s_n0th1ng_y` from the same
audio. The flag was accepted by CTFd.

Sweeping the pitch parameters (−1500…−2600 for segment 1, +2000…+3000 for segment 2) returned the
same character sequence every time, so the transcription does not depend on hitting an exact
shift.

---

## Solver

[`solve.py`](solve.py) runs end-to-end from the original PNG: extracts both archives, pulls the
password out of the pcap, decrypts the WAV, restores the three speech segments, renders the
spectrogram clue, and decodes the documented transcription.

```bash
python -m pip install numpy pillow scipy librosa matplotlib
python solve.py intothevaultyoubreak.png --output artifacts
```

**Speech recognition is deliberately not automated.** The manually recovered fragments are
written into the script and marked as such; listen to the generated `part-1-restored.wav`,
`part-2-restored.wav` and `part-3-restored.wav` to check that step yourself.
`ordered-speech.wav` joins them in the clue's order.

Expected output:

```text
SHA256: b206e80449cb96ce67f8dc15e0aba7f9876f4f6051611f776c01e48a2eb9c145
Hidden ZIP: 8155550 bytes
ZIP password: vaultbreaker
Audio: 44100 Hz; 61.686 seconds
Base64: Y3Nhd3tidXRfdGgzcjNfMXNfbjB0aDFuZ195MHVfY0BuX3RAazN9
Flag: csaw{but_th3r3_1s_n0th1ng_y0u_c@n_t@k3}
```

Tested with Python 3.13.14, NumPy 2.5.3, Pillow 12.3.0, SciPy 1.18.1, librosa 1.0.1 and
Matplotlib 3.11.2. The solver's extracted `vault.wav` is byte-identical to the manually
extracted one.

```python
#!/usr/bin/env python3
# solve.py — Into The Vault You Break (CSAW CTF Finals 2026)
#
# PNG (3-bit LSB) -> zip -> pcap password -> encrypted zip -> WAV -> spoken base64.
#
# usage: python solve.py intothevaultyoubreak.png --output artifacts
# deps:  numpy pillow scipy librosa matplotlib
import argparse
import base64
import hashlib
import io
from pathlib import Path
import re
import struct
import zipfile

import librosa
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from PIL import Image
from scipy.io import wavfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", type=Path)
    parser.add_argument("--output", type=Path, default=Path("vault-solve"))
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    print("SHA256:", hashlib.sha256(args.image.read_bytes()).hexdigest())

    # Row-major pixels, RGB order, three low bits per channel: bit 2, then 1, then 0.
    pixels = np.asarray(Image.open(args.image).convert("RGB")).ravel()
    bits = np.stack([(pixels >> bit) & 1 for bit in (2, 1, 0)], axis=1)
    stream = np.packbits(bits.ravel(), bitorder="big").tobytes()
    size = struct.unpack("<I", stream[:4])[0]        # length prefix: PK sits at offset 4
    payload = stream[4:4 + size]
    assert len(payload) == size and payload.startswith(b"PK\x03\x04")
    (args.output / "vault.zip").write_bytes(payload)
    print("Hidden ZIP:", size, "bytes")

    # Read known archive members directly; no arbitrary archive paths are used.
    with zipfile.ZipFile(io.BytesIO(payload)) as outer:
        pcap = outer.read("vault/vault.pcap")
        inner_bytes = outer.read("vault/innervault.zip")
    (args.output / "vault.pcap").write_bytes(pcap)
    (args.output / "innervault.zip").write_bytes(inner_bytes)
    match = re.search(rb"the key is ([a-z]+)", pcap)
    assert match, "Password clue not found"
    password = match.group(1)
    print("ZIP password:", password.decode())
    with zipfile.ZipFile(io.BytesIO(inner_bytes)) as inner:
        audio_bytes = inner.read("innervault/vault.wav", pwd=password)
    audio_path = args.output / "vault.wav"
    audio_path.write_bytes(audio_bytes)

    sr, pcm = wavfile.read(audio_path)
    assert pcm.dtype == np.int16 and pcm.ndim == 2
    mono = pcm.astype(np.float32).mean(axis=1) / 32768.0
    print("Audio:", sr, "Hz;", round(len(mono) / sr, 3), "seconds")

    # Approximate section boundaries are sufficient: the transitions have pauses.
    # Work at the original sample rate before lowering section 1's pitch; downsampling
    # it first removes useful high-frequency speech information.
    cut1, cut2, speech_end = (round(t * sr) for t in (22.19, 42.23, 61.31))
    restored = {
        1: librosa.effects.pitch_shift(mono[:cut1], sr=sr, n_steps=-24),
        2: librosa.effects.pitch_shift(mono[cut1:cut2], sr=sr, n_steps=24),
        3: mono[cut2:speech_end][::-1].copy(),
    }

    def save_audio(name, samples):
        peak = np.max(np.abs(samples))
        if peak:
            samples = samples / peak * 0.9
        wavfile.write(args.output / name, sr, samples.astype(np.float32))

    for number, samples in restored.items():
        save_audio(f"part-{number}-restored.wav", samples)
    save_audio("ordered-speech.wav", np.concatenate([restored[i] for i in (3, 1, 2)]))

    # The final ~0.37 seconds draw "312" in the spectrogram: the section order.
    fig, ax = plt.subplots(figsize=(12, 4))
    ax.specgram(mono[speech_end:], NFFT=512, Fs=sr, noverlap=504,
                cmap="magma", vmin=-125, vmax=-85)
    ax.set_ylim(500, 3950)
    ax.set_xlabel("Time within the final audio segment (seconds)")
    ax.set_ylabel("Frequency (Hz)")
    ax.set_title("Spectrogram clue: 312")
    fig.tight_layout()
    fig.savefig(args.output / "spectrogram-clue.png", dpi=150)
    plt.close(fig)

    # MANUAL STEP: transcribe the restored speech. The speaker says "capital" before
    # uppercase letters. These fragments document that transcription; they are NOT
    # automatically recognised by this script.
    fragments = {
        1: "jNfMXNfbjB0aDFuZ195",
        2: "MHVfY0BuX3RAazN9",
        3: "Y3Nhd3tidXRfdGgzc",
    }
    encoded = "".join(fragments[i] for i in (3, 1, 2))
    flag = base64.b64decode(encoded, validate=True).decode("ascii")
    assert base64.b64encode(flag.encode()).decode() == encoded
    print("Base64:", encoded)
    print("Flag:", flag)
    (args.output / "flag.txt").write_text(flag + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
```

A minimal extraction-only version, for reference:

```python
px = np.array(Image.open(png).convert('RGB')).reshape(-1)
bits = np.stack([(px >> b) & 1 for b in (2, 1, 0)], 1).reshape(-1)
stream = np.packbits(bits).tobytes()
n = int.from_bytes(stream[:4], 'little')
outer = zipfile.ZipFile(io.BytesIO(stream[4:4 + n]))
pcap = outer.read('vault/vault.pcap')
pw = pcap[pcap.find(b'the key is '):][:23].split()[-1]        # b'vaultbreaker'
inner = zipfile.ZipFile(io.BytesIO(outer.read('vault/innervault.zip')))
open('vault.wav', 'wb').write(inner.read('innervault/vault.wav', pwd=pw))
# then: sox vault.wav p1.wav trim 0 22.3 pitch -2200
#       sox vault.wav p2.wav trim 22.3 20 pitch 2200
#       sox vault.wav p3.wav trim 42.3 reverse
```

---

## Flag

```
csaw{but_th3r3_1s_n0th1ng_y0u_c@n_t@k3}
```

**Provenance.** The flag is the base64 spoken in the WAV. The WAV exists only inside a
password-protected zip; the password is only in the pcap; the pcap is only in the PNG's low bits.
Nothing in the challenge text or the image surface contains it. Accepted by CTFd.

---

## Takeaways

- **Find multi-bit LSB with per-plane randomness statistics.** Comparing neighbour-agreement per
  bit plane between two regions of the image reveals the embedding depth immediately. A 1-bit-only
  scan — the default for most tools — misses this layout entirely.
- **Check every signature at every offset.** A 4-byte length prefix put `PK` at offset 4, which is
  enough to defeat naive carving.
- **Triage a pcap by asking which fields vary.** Everything here was constant except the
  addresses and a single `tcp.len`, which ruled out header covert channels in minutes.
- **For spoken-character audio: split by spectrogram block and undo each transform separately.**
  Prime the recogniser with an `initial_prompt` in the expected "capital X, 3, …" style, then
  resolve the remaining ambiguity by brute force plus readability of the decoded result.
- **Look for an ordering clue before assuming file order.** The segments are not stored in the
  order they are read; `312` says so explicitly, and the first segment decoding to `csaw{` is the
  confirmation.

## Tools

Python (numpy, Pillow, scipy, librosa, matplotlib), `tshark`, `unzip`, `sox` (spectrogram,
reverse, pitch), faster-whisper `small.en`.

> **Note.** This page merges two independently written writeups of the same challenge from the
> same event. Where they differed in presentation — the second documented the `312` spectrogram
> clue, the first documented the bit-plane statistics and the brute-force disambiguation — both
> are kept; their technical conclusions agreed throughout.
