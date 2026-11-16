# Lost in Embedding

| Event | Category | Points | Flag |
|---|---|---|---|
| CSAW CTF Finals 2026 | Misc / AI | 500 | `csaw{d0_0r_d0_n0t_th3r3_1s_n0_try-edd03123cf9f06b9}` |

**TL;DR** — **Embedding inversion.** A deleted record left behind only its 384-dimensional
sentence-transformer vector. The sentence is a fixed template with four slots, each with 48
candidates — 48⁴ ≈ 5.3 million combinations. But the encoder is *pinned and public*
(`all-MiniLM-L6-v2`, mean-pool + L2-normalise) and reproduces the stored vectors **exactly**, so
the vector is not anonymised data at all: it is a lossless lookup key. Coordinate ascent on
cosine similarity converges to cosine ≈ 1.0 in a few hundred forward passes.

---

## 1. The setup

An incident export contains:

- `painting.csv`, `room.csv`, `container.csv`, `window.csv` — 48 `(id, label)` rows each
- `TR-7842.npy` — the 384-d embedding of a deleted record

The sentence is a fixed template:

```
{painting} was transferred to the {room} inside a {container},
with access scheduled during the {window}.
```

Submitting the four correct IDs to the crew channel returns the flag.

---

## 2. Why the embedding is not anonymous

The record was deleted; only "the vector" remains, which *feels* like a privacy-preserving
residue. It is not — three properties together make it fully reversible:

1. **The encoder is pinned and public.** `sentence-transformers/all-MiniLM-L6-v2` at a specific
   revision, with the standard mean-pool + L2-normalise head. Anyone can reproduce it bit for bit.
2. **The input space is tiny and enumerable.** Four slots × 48 candidates each. The template is
   known.
3. **The embedding is deterministic and exact.** Re-encoding the right sentence gives cosine 1.0,
   not merely a high score — so there is an unambiguous correct answer, not a ranked guess.

Brute-forcing all 48⁴ combinations is possible but wasteful at ~5.3M forward passes.

---

## 3. Coordinate ascent

Because each slot contributes roughly independently to the pooled embedding, the similarity
surface is well behaved: fixing three slots and sweeping the fourth gives a clear maximum at the
correct candidate, even when the other three are wrong.

So: start from an arbitrary assignment, repeatedly sweep each slot for the candidate maximising
cosine similarity to the target, and iterate until nothing changes. Each full sweep costs
4 × 48 = **192** encodings instead of 5.3 million.

A handful of random restarts guards against the rare local maximum, and the stopping condition
is unambiguous: **cosine > 0.99999** means the exact combination has been found, and the search
can stop immediately.

The recovered IDs are then POSTed to `/api/submit`, which returns the flag.

---

## 4. Solver

```python
#!/usr/bin/env python3
# solve.py — Lost in Embedding (CSAW CTF Finals 2026, misc 500)
#
# Embedding inversion. A deleted record 'TR-7842' left only its 384-d
# sentence-transformer vector. The sentence is a fixed template with 4 slots
# (painting/room/container/window), each with 48 candidate IDs. The pinned encoder
# (sentence-transformers/all-MiniLM-L6-v2, mean-pool + L2-normalize) reproduces the
# stored vectors EXACTLY, so we match by cosine instead of brute-forcing 48^4.
#
# Method: coordinate ascent — repeatedly sweep each slot for the candidate that
# maximises cosine to the target, with a few random restarts. Converges to cos ~ 1.0
# (the exact combination), which is then POSTed to the crew channel.
#
# Requires the incident-export files (painting.csv, room.csv, container.csv,
# window.csv, TR-7842.npy) and a venv with torch + transformers.
#
# usage: python3 solve.py <host> [export_dir]
#        (model weights download on first run; needs internet once)
import sys, csv, json, requests, numpy as np, torch
from transformers import AutoModel, AutoTokenizer

MODEL = "sentence-transformers/all-MiniLM-L6-v2"
REV   = "1110a243fdf4706b3f48f1d95db1a4f5529b4d41"


def load_csv(path):
    rows = list(csv.reader(open(path)))[1:]
    return [(r[0], r[1]) for r in rows]   # (id, label)


def render(p, r, c, w):
    return (f"{p} was transferred to the {r} inside a {c}, "
            f"with access scheduled during the {w}.")


def main():
    host = sys.argv[1]
    d = (sys.argv[2].rstrip("/") + "/") if len(sys.argv) > 2 else "work/incident-export/"
    torch.set_num_threads(12)
    tok = AutoTokenizer.from_pretrained(MODEL, revision=REV)
    model = AutoModel.from_pretrained(MODEL, revision=REV).to("cpu").eval()

    P, R, C, W = (load_csv(d + f) for f in
                  ("painting.csv", "room.csv", "container.csv", "window.csv"))
    FIELDS = [P, R, C, W]
    target = np.load(d + "TR-7842.npy").astype("float32")
    target = target / np.linalg.norm(target)

    def embed(texts):
        out = []
        for i in range(0, len(texts), 128):
            b = texts[i:i + 128]
            t = tok(b, padding=True, truncation=True, max_length=256, return_tensors="pt")
            with torch.inference_mode():
                h = model(**t).last_hidden_state
                m = t["attention_mask"].unsqueeze(-1)
                pl = (h * m).sum(1) / m.sum(1)          # mean pooling
                pl = torch.nn.functional.normalize(pl, dim=1).numpy()
            out.append(pl)
        return np.concatenate(out)

    def best_for_slot(cur, slot):
        texts = []
        for j in range(len(FIELDS[slot])):
            idx = cur.copy(); idx[slot] = j
            texts.append(render(P[idx[0]][1], R[idx[1]][1], C[idx[2]][1], W[idx[3]][1]))
        sims = embed(texts) @ target
        j = int(sims.argmax()); return j, float(sims[j])

    import random; random.seed(0)
    starts = [[0, 0, 0, 0]] + [[random.randrange(len(f)) for f in FIELDS] for _ in range(5)]
    best = (-1, None)
    for st in starts:
        cur = st.copy(); last = -1
        for _ in range(8):
            for slot in range(4):
                j, s = best_for_slot(cur, slot); cur[slot] = j
            if s == last: break
            last = s
        if s > best[0]: best = (s, cur.copy())
        if s > 0.99999: break       # exact match: stop

    s, cur = best
    ids = {"painting": P[cur[0]][0], "room": R[cur[1]][0],
           "container": C[cur[2]][0], "window": W[cur[3]][0]}
    print(f"[*] best cosine = {s:.8f}")
    print(f"[*] plan = {ids}")
    resp = requests.post(f"http://{host}/api/submit", json=ids, timeout=15)
    print("[*] server:", resp.text)


if __name__ == "__main__":
    main()
```

---

## Flag

```
csaw{d0_0r_d0_n0t_th3r3_1s_n0_try-edd03123cf9f06b9}
```

---

## Takeaways

- **Embeddings are not anonymisation.** A vector plus a public encoder and an enumerable input
  space reconstructs the original text exactly. "We deleted the record and kept only the
  embedding" is a real-world data-retention pattern and a real-world leak.
- **Pin-and-publish cuts both ways.** Reproducibility — the same revision, the same pooling,
  the same normalisation — is a virtue for ML engineering and a gift to the attacker.
- **Exploit decomposability.** Slot contributions to a mean-pooled embedding are near-independent,
  so coordinate ascent turns a 48⁴ product into a 4 × 48 sum: ~192 encodings per sweep instead of
  5.3 million.
- **An exact objective is a free stopping condition.** Cosine 1.0 rather than "best so far" means
  no threshold tuning and no ambiguity about whether you have the answer.

> **Writeup provenance.** Reconstructed from the working solver and its analysis notes; the flag
> was produced live by the script above.
