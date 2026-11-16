# The Final Gateway

| Event | Category | Flag format | Proposed flag |
|---|---|---|---|
| CSAW CTF Finals 2026 | OSINT | `CSAW{LOCATION_NAME}` | `CSAW{BANNERMAN_CASTLE}` |

**TL;DR** — Seven photographs. Recognisable landmarks establish a corridor through the Hudson
Highlands in New York, metadata and an inverted negative narrow it to Route 9D north of Cold
Spring, and an exact Street View match places the final clearing at **Hartsook Lane**. A hidden
EXIF comment — *"The houses were never our destination"* — plus a local community report connect
that lane to **Bannerman Castle on Pollepel Island**.

> **Status.** The photographic location and supporting sources were verified. The destination is
> an inference from the combined clues; **competition acceptance and the exact flag spelling were
> never tested**, so `CSAW{BANNERMAN_CASTLE}` is a proposal, not a confirmed flag.

---

## The handout

Investigators recovered seven photographs and asked for the location associated with the
suspects' final known whereabouts:

```text
bridge.jpg      the-rock.jpg    coffee.png      house.jpeg
mini-bridge.png roadway.png     trees.png
```

---

## Step 1 — Establish the geographic corridor

The working order matters: start with recognisable landmarks, check metadata on everything, and
correct the manipulated image *before* trying to search it.

| Photograph | Identification or clue | Contribution |
|---|---|---|
| `bridge.jpg` | Bear Mountain Bridge | Establishes the Hudson River / Hudson Highlands region |
| `the-rock.jpg` | XMP `pdf:Author` is `William J Moreau` | Identifies the William J. Moreau Popolopen footbridge |
| `coffee.png` | rōz coffee + design, 1806 Route 9D, Cold Spring | Narrows to Cold Spring and Route 9D |
| `house.jpeg` | Cornish Estate ruins, after colour inversion | Corroborates Cold Spring / Hudson Highlands |
| `mini-bridge.png`, `roadway.png` | Pedestrian overpass and staircase at Breakneck Ridge station | Places the road photos on Route 9D north of Cold Spring |

**The bridge.** Tower shape, deck truss and surrounding terrain match Bear Mountain Bridge; the
[New York State Bridge Authority](https://www.nysba.ny.gov/wysiwyg/BMB/BMBpage/bmb_page.htm)
confirms its Hudson River location.

**The rock.** A featureless boulder photo with an unusual XMP field:

```xml
<pdf:Author>William J Moreau</pdf:Author>
```

A `pdf:Author` tag in a JPEG is already anomalous. Searching the name with bridge terms
identifies the [William J. Moreau Popolopen Bridge marker](https://www.hmdb.org/m.asp?m=89612),
whose plaque and nearby pedestrian bridge match the scene. **Check metadata on every image,
including the boring ones** — the least photogenic file carried the most specific clue.

**The café.** The interior matches rōz coffee + design. The
[Cold Spring Chamber of Commerce listing](https://www.coldspringnychamber.com/insiders-guide/rz-coffee-design)
has café photographs and the Route 9D address;
[Village of Cold Spring architectural plans](https://www.coldspringny.gov/DocumentCenter/View/5254/Plans-Dated-082825)
independently confirm the name and address.

**The house.** `house.jpeg` is a photographic negative. Inverting its RGB values reveals the stone
walls and openings of the Cornish Estate ruins — compare with
[Scenic Hudson's Cornish Estate page](https://www.scenichudson.org/explore-the-valley/outdoor-adventures/adventure/cornish-estate-ruins/).
Reverse image search on an inverted photo returns nothing; invert first, then search.

**The road photos.** Both match the Breakneck Ridge station pedestrian overpass — staircase,
steel truss, roadside guardrail and rock cutting all line up:

```text
Panorama:    c6jkwqNU5Wl9kVujDoWzUw
Date:        May 2025
Coordinates: 41.4502961, -73.9821132
```

Together these support a route north through the Hudson Highlands toward Cold Spring and
Breakneck Ridge. This is a geographic reconstruction — the pictures alone do not establish an
independently timestamped itinerary.

---

## Step 2 — Locate the final clearing precisely

`trees.png` is the least distinctive photograph: forest, a gravel clearing, a mailbox stand. The
key decision is **not to try to identify the forest globally**, but to search along the
already-confirmed Route 9D corridor. That turns an impossible problem into a bounded one.

Comparing the mailbox stand, stone edging, utility pole, tree trunks and gravel clearing with
Street View gives an exact match at the entrance to **Hartsook Lane**:

```text
Coordinates: 41.4559250420, -73.9816768733
Panorama:    sC-4NLTVk7rEIgulbjfIEA
Date:        May 2025
```

Expanding the view beyond the challenge crop exposes a **HARTSOOK LN** street sign — the crop was
chosen to exclude it.

### Verifying the match numerically

A visual match is a claim; SIFT makes it a measurement. Using 2,000 requested features for the
challenge crop, 6,000 for the cached 2048 × 1024 panorama, a 0.77 nearest-neighbour ratio test
and a 5-pixel RANSAC threshold:

```text
Ratio-test matches: 308
RANSAC inliers:     197
```

The next-best candidate in the corridor search had **five** inliers. A 197-vs-5 separation is not
a close call — that gap is what makes the identification defensible rather than a hunch.

SIFT verifies *image correspondence*; the geographic coordinates come from the panorama's own
metadata, not from SIFT.

---

## Step 3 — Resolve the destination beyond the houses

`trees.png` carries an EXIF `UserComment`:

```text
The houses were never our destination.
```

That explicitly rules out the lane's residences and tells you the answer is something the lane
*leads to* or *looks at*.

Searching **Hartsook Lane Bannerman** reaches the Hudson Highlands Fjord Trail's
[20 November 2022 community forum summary](https://hhft.org/wp-content/uploads/2023/01/HHFT-11.20.22-Summary_Findings-02-opt.pdf).
Page 7 connects Hartsook and Coris Lanes with views of Bannerman Castle and describes a mapping
problem involving Bannerman's Island Overlook. Page 41 states plainly:

> Waze/Google sends Bannerman Island visitors to Hartsook Lane

That is a specific, documented link between the matched clearing and an island destination.
Combined with the metadata excluding the houses, it supports **Bannerman Castle** as the intended
answer. The [Bannerman Castle Trust](https://bannermancastle.org/) confirms the castle is on
Pollepel Island, also called Bannerman Island.

This final step is an inference. The photo match itself establishes Hartsook Lane.

---

## Reproduction

This is an OSINT solve: landmark identification and source interpretation are manual. The
accompanying script verifies the local metadata, reverses the negative, and reproduces the final
image match. It does not discover the destination from arbitrary photographs.

```bash
python -m pip install pillow numpy opencv-python
python verify.py chal --panorama artifacts/matched-panorama.jpg --output artifacts
```

To inspect the location independently, open Street View near **41.455925, -73.981677** and select
the May 2025 imagery; use the panorama ID above if the default imagery has changed.

Verified output with OpenCV 5.0.0:

```text
trees.png UserComment: The houses were never our destination.
the-rock.jpg XMP pdf:Author: William J Moreau
SIFT ratio-test matches: 308
RANSAC inliers: 197
Photographed location: Hartsook Lane entrance, Route 9D
Inferred destination: Bannerman Castle, Pollepel Island
Proposed flag (unsubmitted): CSAW{BANNERMAN_CASTLE}
```

The script also saves `evidence.json`, `house-positive.png`, `trees-feature-match.jpg` and
`located-clearing.jpg`.

```python
#!/usr/bin/env python3
# verify.py — The Final Gateway: verify local evidence; geography is interpreted manually.
#
# Dependencies: pillow numpy opencv-python
# Usage: python verify.py PHOTO_DIR --panorama MATCHED_PANORAMA.jpg
import argparse
import hashlib
import json
from pathlib import Path
import re

import cv2
import numpy as np
from PIL import Image, ImageOps


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("photos", type=Path)
    parser.add_argument("--panorama", type=Path, required=True,
                        help="Cached 2048x1024 panorama sC-4NLTVk7rEIgulbjfIEA")
    parser.add_argument("--output", type=Path, default=Path("artifacts"))
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)

    tree_path = args.photos / "trees.png"
    with Image.open(tree_path) as tree:
        comment = tree.getexif().get_ifd(34665)[37510]
    assert comment.startswith(b"ASCII\x00\x00\x00")
    comment = comment[8:].decode("ascii")
    rock = (args.photos / "the-rock.jpg").read_bytes()
    author = re.search(rb"<pdf:Author>(.*?)</pdf:Author>", rock).group(1).decode()
    ImageOps.invert(Image.open(args.photos / "house.jpeg").convert("RGB")).save(
        args.output / "house-positive.png")
    print("trees.png UserComment:", comment)
    print("the-rock.jpg XMP pdf:Author:", author)

    # Match the challenge crop against the independently located panorama.
    target = cv2.imread(str(tree_path), cv2.IMREAD_GRAYSCALE)
    panorama = cv2.imread(str(args.panorama), cv2.IMREAD_GRAYSCALE)
    assert target is not None and panorama is not None
    cv2.setNumThreads(1)
    cv2.setRNGSeed(0)
    k1, d1 = cv2.SIFT_create(nfeatures=2000).detectAndCompute(target, None)
    k2, d2 = cv2.SIFT_create(nfeatures=6000).detectAndCompute(panorama, None)
    pairs = cv2.BFMatcher().knnMatch(d1, d2, k=2)
    good = [m for m, n in pairs if m.distance < 0.77 * n.distance]
    assert len(good) >= 4, "Insufficient feature matches"
    source = np.float32([k1[m.queryIdx].pt for m in good])
    destination = np.float32([k2[m.trainIdx].pt for m in good])
    matrix, mask = cv2.findHomography(source, destination, cv2.RANSAC, 5)
    assert matrix is not None and mask is not None
    inliers = [m for m, keep in zip(good, mask.ravel()) if keep]
    print("SIFT ratio-test matches:", len(good))
    print("RANSAC inliers:", len(inliers))
    drawing = cv2.drawMatches(target, k1, panorama, k2,
                              sorted(inliers, key=lambda m: m.distance)[:70], None,
                              flags=cv2.DrawMatchesFlags_NOT_DRAW_SINGLE_POINTS)
    cv2.imwrite(str(args.output / "trees-feature-match.jpg"), drawing)

    h, w = target.shape
    corners = np.float32([[0, 0], [w - 1, 0], [w - 1, h - 1], [0, h - 1]])
    projected = cv2.perspectiveTransform(corners.reshape(-1, 1, 2), matrix)
    color = cv2.imread(str(args.panorama))
    cv2.polylines(color, [np.int32(projected)], True, (0, 255, 0), 3)
    cv2.imwrite(str(args.output / "located-clearing.jpg"), color)

    evidence = {
        "tree_comment": comment,
        "rock_author": author,
        "ratio_matches": len(good),
        "ransac_inliers": len(inliers),
        "panorama_sha256": hashlib.sha256(args.panorama.read_bytes()).hexdigest(),
        # Coordinates come from panorama metadata, not from SIFT.
        "panorama_id": "sC-4NLTVk7rEIgulbjfIEA",
        "panorama_coordinates": [41.45592504203359, -73.98167687333655],
        "panorama_date": "May 2025",
        "photographed_location": "Hartsook Lane entrance, Route 9D",
        "inferred_destination": "Bannerman Castle, Pollepel Island",
        "proposed_flag": "CSAW{BANNERMAN_CASTLE}",
        "contest_acceptance_verified": False,
    }
    (args.output / "evidence.json").write_text(json.dumps(evidence, indent=2), encoding="utf-8")
    print("Photographed location:", evidence["photographed_location"])
    print("Inferred destination:", evidence["inferred_destination"])
    print("Proposed flag (unsubmitted):", evidence["proposed_flag"])


if __name__ == "__main__":
    main()
```

---

## Proposed flag

```text
CSAW{BANNERMAN_CASTLE}
```

**Status:** proposed, based on the destination inference. No successful contest submission was
recorded, so the accepted spelling and capitalisation remain unverified.

---

## Takeaways

- **Check metadata on every file, especially the dull ones.** A `pdf:Author` field in a JPEG and
  an EXIF `UserComment` carried two of the three decisive clues.
- **Repair manipulated images before searching them.** An inverted photo defeats reverse image
  search entirely; inverting it first turned it into an identifiable landmark.
- **Use the confirmed corridor to bound the hard image.** `trees.png` is unidentifiable globally
  and trivial to find once the search is restricted to a few kilometres of Route 9D.
- **Quantify visual matches.** 197 RANSAC inliers against a next-best of 5 converts "it looks
  like the same place" into evidence.
- **Local civic documents are searchable OSINT.** A community-forum PDF stating that navigation
  apps misroute Bannerman Island visitors to Hartsook Lane was the link no map could provide.
- **Say which step is inference.** The photo match is proven; the destination is reasoned. Keeping
  those separate is what makes the writeup trustworthy.
