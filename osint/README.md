# OSINT

| Challenge | Approach | Flag |
|---|---|---|
| [The Final Gateway](the-final-gateway/) | Landmark identification, EXIF/XMP clues, negative inversion, Street View matching verified with SIFT/RANSAC | `CSAW{BANNERMAN_CASTLE}` *(proposed, unsubmitted)* |
| [Pokémon Talk](pokemon-talk/) | Repeating-key XOR whose key is also the location clue, then an exact-phrase Reddit search | `CSAW{p0k3m0n_talk}` |

**Recurring theme:** both challenges put the *method* in the artifact rather than the answer. The
XOR key was the geography; the EXIF comment ruled out the wrong reading of an already-confirmed
location. Check metadata on every file, and treat decryption keys as content in their own right.
