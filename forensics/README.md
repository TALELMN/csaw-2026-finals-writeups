# Forensics & Steganography

Three audio and image challenges — all multi-fragment, and all requiring a *measurement* rather
than a guess just to locate the payload.

| Challenge | Bug class | Flag |
|---|---|---|
| [Into The Vault You Break](into-the-vault-you-break/) | 3-bit LSB PNG → zip → pcap password → encrypted zip → WAV of spoken base64, reordered by a spectrogram clue | `csaw{but_th3r3_1s_n0th1ng_y0u_c@n_t@k3}` |
| [You Can't Steal My Stuff](you-cant-steal-my-stuff/) | Reversed speech + WAV `ICRD` metadata + forward speech, with two fragments encrypted by Vigenère **over the base64 text** | `csaw{but_y0u_c@nt_st3@l_my_h3@rt}` |
| [Music Security Department 2](music-security-department-2/) | Text in the stereo-difference spectrogram + melody scale degrees as hex + 300-baud Bell 202 FSK | `csaw{music-is-my-favorite-love-language}` |

**Recurring themes:**

- **Measure, do not eyeball.** Per-bit-plane neighbour agreement exposed a 3-bit LSB embedding
  that a 1-bit scan misses; a channel-correlation drop to zero exposed a hidden right-channel
  voice; harmonic scoring beat peak-picking on the melody.
- **Split every channel and render every difference.** `L − R` was a hiding place in two of the
  three.
- **Expect the flag in several pieces, in several encodings** — and look for an explicit ordering
  clue before assuming the fragments are stored in order.
