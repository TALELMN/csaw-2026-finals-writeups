# You Can't Steal My Stuff

| Event | Category | Flag |
|---|---|---|
| CSAW CTF Finals 2026 | Forensics / Steganography (audio) | `csaw{but_y0u_c@nt_st3@l_my_h3@rt}` |

> look closely, and listen....

**TL;DR** — The flag is split three ways: **reversed speech**, a **WAV metadata field**, and
**forward speech**. Two of the three pieces are encrypted, and a voice pitched up ~28× in the
right channel names the key. The cipher is the unusual part — **Vigenère applied to the base64
text**, not base64 of a Vigenère ciphertext — which is why both strings look like base64 and
decode to garbage.

---

## 1. Inspecting the file

```bash
file youcanstealmystuff.wav
exiftool youcanstealmystuff.wav
ffprobe -hide_banner youcanstealmystuff.wav
```

16-bit PCM, stereo, 44,100 Hz, about **34.21 seconds**.

The RIFF `LIST/INFO` metadata:

```text
ICMT (comment): csaw{this_is_not_the_flag}
ICRD (date):    Y0MgrX9swKRRfF8=
IGNR (genre):   Country
```

The comment is an obvious decoy — and a useful one, because it confirms the author hid things in
metadata. The *date* field is the real find: not a date at all, but a base64-shaped string.
Decoding it directly gives non-printable bytes:

```text
63 43 20 ad 7f 6c c0 a4 51 7c 5f
```

So `Y0MgrX9swKRRfF8=` is an **encrypted** fragment, not a plain one. Park it.

---

## 2. Comparing the stereo channels

```python
import numpy as np
from scipy.io import wavfile

sr, audio = wavfile.read("youcanstealmystuff.wav")
left, right = audio[:, 0], audio[:, 1]
wavfile.write("left.wav", sr, left)
wavfile.write("right.wav", sr, right)
```

This is not ordinary stereo. The channels behave differently by region:

| Time | Observation |
|---|---|
| 0–15.8 s | Both channels nearly identical (correlation ≈ 1.000) |
| 15.8–22.1 s | Right ≈ 0.42× copy of left (fitted gain 0.416, correlation ≈ 0.992) |
| 22.1–26.9 s | Right carries a *separate* high-frequency, speech-like signal (correlation ≈ 0) |
| 26.9 s–end | The hidden high-pitched segment ends |

A correlation of ~0 in one window of an otherwise near-mono file is the whole discovery: there is
content in the right channel that **mono playback would average away**. Always split the channels.

---

## 3. Fragment 1 — reversed speech

The first ~15.8 seconds sound wrong played forward. Reversed, they are intelligible:

```python
from scipy.io import wavfile
sr, audio = wavfile.read("youcanstealmystuff.wav")
cut = int(15.8 * sr)
wavfile.write("first_reversed.wav", sr, audio[:cut, 0][::-1])
```

The voice spells:

```text
C S A W, open bracket, B U T, underscore, Y zero U, underscore
```

→ `csaw{but_y0u_` (the `0` is a digit zero).

This fragment is **plaintext** — only the other two are encrypted.

---

## 4. Fragment 3 — forward speech

From about **16.8 s** onward the main voice reads a character sequence forward:

```text
B, capital I, X, T, S, capital W, capital G, capital H, G, E, capital V, nine
```

Lowercasing anything not called "capital":

```text
bIxtsWGHgeV9
```

`B`, `X` and `S` are acoustically ambiguous here. Resist the urge to re-listen forever — the
decryption below is an independent consistency check that resolves them.

Like the metadata string, this looks like base64 and decodes to nothing readable. Two separate
"base64 that isn't base64" strings is a strong hint that one transformation applies to both.

---

## 5. The hidden key

The right-channel audio between **22.1 and 26.9 s** is not noise. Its spectrogram shows harmonic
structure characteristic of speech — just far above any human speaking pitch.

Measuring: the normal voice sits near **142 Hz**; the hidden fundamental near **4,055 Hz**.

```
4055 / 142 ≈ 28.5×   ≈  58 semitones
```

To recover it, extract the segment, resample it down to lower the pitch, then **time-compress it
back to its original duration** with a pitch-preserving stretch (WSOLA or similar):

```python
from scipy.io import wavfile
sr, audio = wavfile.read("youcanstealmystuff.wav")
hidden = audio[int(22.1 * sr):int(26.9 * sr), 1]
wavfile.write("hidden_high_pitch.wav", sr, hidden)
```

Simply playing it slower lowers the pitch **but also lengthens the audio**; relabelling the
sample rate alone is not enough — the extra time-compression step is required.

The recovered speech consistently begins **"The key is …"**, with the rest hard to make out.
That is expected and worth understanding: a 28.5× upward shift leaves only about
`22050 / 28.5 ≈ 774 Hz` of the original voice's bandwidth inside a 44.1 kHz recording, so most of
the consonant information is simply gone. Audio hidden this way is deliberately lossy.

The key finally established by the cryptanalysis is:

```text
almostthere
```

"The key is almost there" fits the audio — but the decryption below establishes it far more
firmly than the speech ever could.

---

## 6. Identifying the cipher

The key realisation: the encrypted strings are **Vigenère-shifted base64**, not base64 of
Vigenère-encrypted plaintext. That is why the character set still *looks* like base64 while
decoding to noise — a letter-only shift preserves the alphabet but destroys the bits.

Derive the key from a crib. Given the challenge title and the other fragments, the last piece
should plausibly start with `my_`:

```text
"my_" in base64  =  bXlf
observed prefix  =  bIxt
```

Letter-by-letter shifts:

```text
b -> b :  0 = A
X -> I : 11 = L
l -> x : 12 = M
f -> t : 14 = O
```

The key starts **ALMO**. Trying the natural continuation `almost` against the metadata fragment
produces `c@nt_s` — which fits the sentence — and extending to **`almostthere`** makes *both*
encrypted pieces decode cleanly. Two independent ciphertexts agreeing on one key is conclusive.

The transformation:

```text
Vigenère decrypt (letters only, case preserved)
        ↓
   base64 decode
        ↓
    plaintext
```

Digits and `=` pass through unchanged, and **only letters advance the key position**.

---

## 7. Solver

```python
#!/usr/bin/env python3
# solve.py — You Can't Steal My Stuff: Vigenere-over-base64 fragments.
import base64


def vig_decrypt(ciphertext, key):
    result = []
    i = 0
    for ch in ciphertext:
        if ch.isascii() and ch.isalpha():
            base = ord("A") if ch.isupper() else ord("a")
            shift = ord(key[i % len(key)]) - ord("a")
            result.append(chr((ord(ch) - base - shift) % 26 + base))
            i += 1          # only letters advance the key position
        else:
            result.append(ch)
    return "".join(result)


key = "almostthere"

metadata = "Y0MgrX9swKRRfF8="      # ICRD field
spoken = "bIxtsWGHgeV9"            # forward speech, ~16.8 s onward

middle_b64 = vig_decrypt(metadata, key)
last_b64 = vig_decrypt(spoken, key)

middle = base64.b64decode(middle_b64).decode("ascii")
last = base64.b64decode(last_b64).decode("ascii")

print("Metadata:", metadata, "->", middle_b64, "->", middle)
print("Speech:  ", spoken, "->", last_b64, "->", last)
print("Flag:", "csaw{but_y0u_" + middle + last)
```

```text
Metadata: Y0MgrX9swKRRfF8= -> Y0BudF9zdDNAbF8= -> c@nt_st3@l_
Speech:   bIxtsWGHgeV9 -> bXlfaDNAcnR9 -> my_h3@rt}
Flag: csaw{but_y0u_c@nt_st3@l_my_h3@rt}
```

This also settles the uncertain spoken characters: the exact sequence `bIxtsWGHgeV9` is the one
that yields a coherent ending.

---

## 8. Putting it together

| Fragment | Location | Plaintext |
|---|---|---|
| First | Reversed speech, 0–15.8 s | `csaw{but_y0u_` |
| Middle | Metadata `ICRD` field | `c@nt_st3@l_` |
| Last | Forward speech, ~16.8 s onward | `my_h3@rt}` |
| Key | Hidden high-pitched right-channel voice, confirmed by cryptanalysis | `almostthere` |

---

## Flag

```
csaw{but_y0u_c@nt_st3@l_my_h3@rt}
```

**Verification status.** The metadata, WAV format, channel comparisons and the Vigenère/base64
output can all be checked directly against the original file and are independently reproducible.
The speech transcriptions and pitch measurements follow the documented audio analysis. The flag
has **not** been confirmed by a scoreboard submission.

---

## Takeaways

- **Inspect both the metadata and both channels before anything else.** An `ICRD` "date" that is
  not a date, and a 4.8-second window where channel correlation drops to zero, were the two
  discoveries that made the rest possible.
- **"Looks like base64 but decodes to garbage" usually means a transform on the text, not the
  bytes.** Vigenère-over-base64 preserves the alphabet, so the usual sanity check passes while
  the decode fails.
- **Let the cryptanalysis resolve the audio.** Ambiguous spoken letters (B/X/S, M/N) are far
  better disambiguated by "which reading decrypts to English" than by re-listening.
- **A crib beats a key search.** Guessing `my_` as the final fragment's prefix gave four key
  letters immediately, and the natural word completion did the rest.
- **Extreme pitch shifts are lossy by construction.** Shifting a voice up 28× leaves <800 Hz of
  original bandwidth; expect to recover the gist, not the exact words, and plan to confirm it
  elsewhere.
