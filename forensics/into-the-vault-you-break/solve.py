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
