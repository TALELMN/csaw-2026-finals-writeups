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
