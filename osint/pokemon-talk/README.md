# Pokémon Talk

| Event | Category | Flag |
|---|---|---|
| CSAW CTF Finals 2026 | OSINT | `CSAW{p0k3m0n_talk}` |

**TL;DR** — An encrypted message and a Pokémon-flavoured quote. Decrypt the ciphertext with
repeating-key XOR under the key `Kyoto`; the plaintext tells you to stop asking an AI and start
searching. The quote is a verbatim Reddit post title, and the location clue narrows it to Kyoto,
Japan. The flag is in the post's comments.

---

## 1. Decrypting the hint

The provided ciphertext decrypts under **repeating-key XOR with the key `Kyoto`**:

```text
AI isn't gonna help you, use other forms,
that quote might be useful, narrow down your search
```

Three actionable instructions, plus one bonus: **the key itself is the location**. It is easy to
treat `Kyoto` as an arbitrary password and discard it after decrypting — but it is the
geographical clue that the plaintext then tells you to use.

Reading the plaintext as instructions:

- Do not expect a language model to solve this.
- Use conventional OSINT methods.
- The quote from the challenge is the search query.
- A location narrows the search.

---

## 2. The quote

The challenge includes:

> So that's where Bulbasaur and Squirtle went

That is not flavour text — it is phrased like a post title, so search it as an **exact-match
query** rather than paraphrasing it.

---

## 3. Finding the post

Searching the exact phrase leads to a post on **r/MandJTV** with precisely that title:

> So that's where Bulbasaur and Squirtle went

The body reads:

```text
Spotted at the Pokemon [Center] in Kyoto, Japan
```

Kyoto — matching the XOR key — confirms this is the intended post rather than a coincidental
match.

**Post:** <https://www.reddit.com/r/MandJTV/comments/1u5dc8z/so_thats_where_bulbasaur_and_squirtle_went/>

---

## 4. Recovering the flag

Inspecting the post and its **comments** reveals the flag.

---

## Flag

```
CSAW{p0k3m0n_talk}
```

---

## Takeaways

- **Analyse the ciphertext before searching for the flag.** The decrypted plaintext contained the
  method, not the answer — a deliberate design that rewards working the challenge in order.
- **The key is a clue.** `Kyoto` was both the XOR key and the geographic filter; crypto material
  in an OSINT challenge is rarely arbitrary.
- **Quote distinctive phrases exactly.** Search engines reward verbatim strings; paraphrasing a
  post title throws away the signal that makes it findable.
- **Read the comments.** The post body confirmed the location; the flag was one level deeper, in
  the discussion under it.
- **"AI isn't gonna help you" is a fair warning.** The flag lives in a specific post's comment
  thread — retrievable by searching, not by recall.
