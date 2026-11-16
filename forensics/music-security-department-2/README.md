# Music Security Department 2

| Event | Category | Flag |
|---|---|---|
| CSAW CTF Finals 2026 | Forensics (audio) | `csaw{music-is-my-favorite-love-language}` |

> I made a song for the competition. 140 BPM, A# Major.

**TL;DR** — One song, three completely different encodings, one per flag fragment:
**text drawn in the stereo-difference spectrogram**, **hex digits encoded as scale degrees in the
melody**, and **repeated 300-baud FSK packets** at the end. The challenge description is not
flavour — "140 BPM, A# Major" is the decoding key for the middle fragment.

**Input:** 44,100 Hz stereo 16-bit PCM WAV, 7,333,200 frames (166.286 s).

```
SHA-256: 799bd2b2f57d279713f577813e808ab7f898209469af7fc081ef1488f42e8476
```

---

## Fragment 1 — the stereo-difference spectrogram

Subtract the right channel from the left. Content panned identically in both channels (the
music) cancels; anything encoded as a channel *difference* survives. Here that exposes text at
**29.4–35.2 s** in the **5–7 kHz** band, invisible in either channel alone.

An STFT with a 2,048-sample window and 512-sample hop makes it readable:

```text
csaw{music-is-my-
```

The separators sit at mid-letter height, which confirms they are **hyphens, not underscores** —
worth checking carefully, because a CTF flag with hyphens is unusual enough to second-guess.

This fragment is transcribed visually; the solver renders the image but does not attempt OCR.

---

## Fragment 2 — the melody as hexadecimal

At 140 BPM a beat is `60/140` s and a four-beat bar is `12/7` s. (Bar numbers below are
zero-based, with bar 0 at the start of the file.) The payload passage is around **88.5–105.2 s**.

The encoding: take consecutive positions in the A# major scale starting at **A#3**, and read them
as hex digits `0`–`f`. The table uses the enharmonically equivalent B♭ major spelling for
readability. **Octave information must be preserved** — the scale spans more than one octave, so
pitch class alone is ambiguous.

| Hex | Note | MIDI | | Hex | Note | MIDI |
|---|---|---|---|---|---|---|
| 0 | B♭3 | 58 | | 8 | C5 | 72 |
| 1 | C4 | 60 | | 9 | D5 | 74 |
| 2 | D4 | 62 | | a | E♭5 | 75 |
| 3 | E♭4 | 63 | | b | F5 | 77 |
| 4 | F4 | 65 | | c | G5 | 79 |
| 5 | G4 | 67 | | d | A5 | 81 |
| 6 | A4 | 69 | | e | B♭5 | 82 |
| 7 | B♭4 | 70 | | f | C6 | 84 |

### Why a naive peak-picker fails

Taking the single strongest FFT bin per note is unreliable: on many instruments a harmonic
exceeds the fundamental, so the detector confidently reports the wrong note an octave or a fifth
up. Instead, **score each candidate note by the geometric mean of the spectral amplitudes near
its 1st, 2nd, 3rd, 5th and 6th harmonics.** A note whose whole harmonic series is present wins;
a lone strong partial does not. Sample *inside* each note, away from transitions, and keep
repeated pitches as separate events.

The sixteen note events decode two at a time:

| Notes | Hex byte | ASCII |
|---|---|---|
| A4, A4 | 66 | `f` |
| A4, C4 | 61 | `a` |
| B♭4, A4 | 76 | `v` |
| A4, C6 | 6f | `o` |
| B♭4, D4 | 72 | `r` |
| A4, D5 | 69 | `i` |
| B♭4, F4 | 74 | `t` |
| A4, G4 | 65 | `e` |

```
6661766f72697465  ->  favorite
```

The solver contains the manually located sampling positions (as beats after bar 48) and extracts
their pitches from the WAV — **the word itself is not hardcoded**. This is a targeted
transcription of the payload passage, not a claim that the whole song decodes to text.

---

## Fragment 3 — repeated FSK packets

Four bursts at bars 80, 84, 88 and 92 (≈ 137.143, 144.000, 150.857 and 157.714 s), each starting
about 0.25 s into its bar.

Parameters: **300 baud**, **1,200 Hz = bit 1**, **2,200 Hz = bit 0**, UART **8N1** framing — a
zero start bit, eight data bits least-significant-first, and a one stop bit. These are Bell 202
modem parameters, which is a good guess to try first on any two-tone audio payload.

At 44,100 Hz each bit spans exactly **147 samples**, so there is no fractional-sample drift to
correct — compare sliding correlations at both frequencies, scan the sampling phase, and reject
any frame with an invalid start or stop bit. The framing bits are effectively a free checksum:
a wrong phase produces frames that fail them, so the correct alignment identifies itself.

Each burst independently yields the same 15 bytes:

```text
-love-language}
```

Four identical independent decodes is the verification.

---

## Assembly

Join all three without dropping either boundary hyphen:

```text
csaw{music-is-my-  +  favorite  +  -love-language}
```

---

## Reproduction

```bash
python -m pip install numpy scipy matplotlib
python solve.py challenge.wav
```

Writes `prefix.png` and `recovered_flag.txt`. Check the rendered image against the visually
transcribed prefix written into the script. Tested with Python 3.13.14, NumPy 2.5.3, SciPy 1.18.1
and Matplotlib 3.11.2.

```python
#!/usr/bin/env python3
# solve.py — Music Security Department 2: render prefix, decode melody + FSK.
import argparse
from collections import Counter
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from scipy import signal
from scipy.io import wavfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("wav", type=Path)
args = parser.parse_args()
sr, raw = wavfile.read(args.wav)
assert sr == 44100 and raw.ndim == 2 and raw.shape[1] == 2
assert raw.dtype == np.int16
audio = raw.astype(np.float64) / 32768
mono = audio.mean(axis=1)
beat_seconds = 60 / 140

# --- fragment 1: stereo difference spectrogram (visual transcription, not OCR) ---
start, end = 29.0, 36.0
side = audio[round(start * sr):round(end * sr), 0] - audio[
    round(start * sr):round(end * sr), 1]
f, t, z = signal.stft(side, sr, nperseg=2048, noverlap=1536)
fig, ax = plt.subplots(figsize=(16, 4))
ax.pcolormesh(t + start, f, 20 * np.log10(abs(z) + 1e-9),
              shading="auto", vmin=-75, vmax=-38)
ax.set(xlim=(29, 36), ylim=(4800, 7200),
       xlabel="Time (s)", ylabel="Frequency (Hz)")
fig.tight_layout()
fig.savefig("prefix.png", dpi=120)
plt.close(fig)
prefix = "csaw{music-is-my-"  # read from the generated prefix.png
print("Visual prefix:", prefix)

# --- fragment 2: sixteen scale positions from A#3/Bb3 encode hex ---
scale = np.array([58, 60, 62, 63, 65, 67, 69, 70,
                  72, 74, 75, 77, 79, 81, 82, 84])
# Manually located note-interior sample positions, in beats after bar 48 (zero-based).
# These are analysis windows, not note-onset times.
positions = [14.5, 16.7, 19.5, 21.5, 23.5, 24.3, 25.5, 32.7,
             34.8, 37, 40, 46.8, 48.8, 50.5, 51.8, 53.5]
nibbles = []
for position in positions:
    timestamp = (48 * 4 + position) * beat_seconds
    clip = mono[round(timestamp * sr):round((timestamp + .12) * sr)]
    spectrum = abs(np.fft.rfft(clip * np.hanning(len(clip)), 65536))
    frequencies = np.fft.rfftfreq(65536, 1 / sr)
    scores = []
    for note in scale:
        fundamental = 440 * 2 ** ((note - 69) / 12)
        # Geometric mean over several harmonics: a lone strong partial cannot win.
        energies = [spectrum[abs(frequencies - fundamental * h) < 10].max()
                    for h in (1, 2, 3, 5, 6)]
        scores.append(np.exp(np.mean(np.log(np.array(energies) + .01))))
    nibble = int(np.argmax(scores))
    nibbles.append(nibble)
    print(f"{timestamp:7.3f}s: MIDI {scale[nibble]:2d} -> {nibble:x}")
hex_text = "".join(f"{n:x}" for n in nibbles)
middle = bytes.fromhex(hex_text).decode("ascii")
print("Melody:", hex_text, "->", middle)

# --- fragment 3: binary FSK, 1200 Hz = 1, 2200 Hz = 0, 300 baud, UART 8N1 ---
samples_per_bit = sr // 300  # exactly 147 samples at this sample rate
packets = []
for bar in (80, 84, 88, 92):
    start = bar * 4 * beat_seconds
    clip = mono[round(start * sr):round((start + 1) * sr)]
    t = np.arange(len(clip)) / sr
    powers = [abs(signal.convolve(clip * np.exp(-2j * np.pi * f * t),
                                  np.ones(samples_per_bit), mode="same"))
              for f in (1200, 2200)]
    bits = (powers[0] > powers[1]).astype(int)
    candidates = Counter()
    for phase in range(samples_per_bit):
        sampled = bits[phase::samples_per_bit]
        # The packet starts about 0.25 seconds into each bar.
        for offset in range(65, 85):
            frames = sampled[offset:offset + 150].reshape(15, 10)
            if frames[:, 0].sum() or (1 - frames[:, 9]).sum():
                continue  # require every start bit = 0 and stop bit = 1
            values = frames[:, 1:9] @ (2 ** np.arange(8))
            packet = bytes(values.astype(np.uint8))
            if all(32 <= value < 127 for value in packet):
                candidates[packet] += 1
    if not candidates:
        raise RuntimeError(f"No clean FSK packet at bar {bar}")
    packet = candidates.most_common(1)[0][0]
    packets.append(packet)
    print(f"FSK bar {bar}: {packet.decode('ascii')}")
assert len(set(packets)) == 1, "Repeated FSK packets disagree"
flag = prefix + middle + packets[0].decode("ascii")
Path("recovered_flag.txt").write_text(flag + "\n", encoding="utf-8")
print("Flag:", flag)
```

Relevant output:

```text
Visual prefix: csaw{music-is-my-
Melody: 6661766f72697465 -> favorite
FSK bar 80: -love-language}
FSK bar 84: -love-language}
FSK bar 88: -love-language}
FSK bar 92: -love-language}
Flag: csaw{music-is-my-favorite-love-language}
```

---

## Flag

```
csaw{music-is-my-favorite-love-language}
```

All three fragments were checked against the supplied audio. Acceptance by the competition's flag
checker was not tested.

---

## Takeaways

- **Treat the challenge description as parameters.** "140 BPM, A# Major" defines the bar grid and
  the scale — without both, the melody fragment is undecodable.
- **The stereo difference is a first-class hiding place.** `L − R` cancels centred content and
  exposes anything encoded as an inter-channel difference; always render it alongside the normal
  spectrogram.
- **Score notes across harmonics, never on a single peak.** Octave and fifth errors from
  dominant partials are the default failure mode of naive pitch detection.
- **Protocol framing is free error detection.** UART start/stop bits let a demodulator find its
  own sampling phase and reject bad alignments, and four identical bursts verify the result.
- **Repeated payloads are an invitation to cross-check.** If a challenge sends the same packet
  four times, decode all four and assert they agree.

## Attribution

Initial fragment analysis — locating the spectrogram prefix and identifying the FSK ending — is
credited to prior work by another solver; both were independently reproduced here. The additional
work recovered and verified the melody-encoded middle word.
