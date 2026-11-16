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
