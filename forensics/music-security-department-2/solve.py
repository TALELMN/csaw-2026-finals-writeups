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
