# Processing all of That

| Event | Category | Points | Flag |
|---|---|---|---|
| CSAW CTF Finals 2026 | Misc | 499 | `csaw{st1ll_0p3n_0n_thr33}` |

> You have been dropped into a monitoring shell. Something is running. Figure out what it's holding.

**TL;DR** — A restricted shell allows a handful of monitoring tools with **no arguments** and no
shell metacharacters. The jail cannot be escaped, so the answer must come out of the allowed
tools themselves. `top` has been preconfigured with custom **Inspect (`Y`)** entries: `State` on
one collector names a delegate PID, and `Held` on that delegate prints the file it still has open
— which contains the flag.

Per-player instance over `nc <ip> 1337`, reached through the CTF WireGuard VPN.

---

## 1. The shell

```
  restricted shell
  one token per line. ? for commands.

> ?
  free        htop        ps          vmstat      uptime
  btop        hostname    top         arch        w
  pstree      id          tty
```

`id` gives `uid=1337(ctf)`. Arguments are refused outright:

```
> ps aux
% one token only, no arguments.
```

---

## 2. Confirming the jail is actually closed

It is worth proving this before spending time on it. The filter is a strict whitelist on the
exact token, with no shell layer behind it at all:

| Input | Response |
|---|---|
| `sh`, `ls`, `cat`, `lsof`, `PS` | `% unknown command` |
| `/usr/bin/id`, `../usr/bin/id` | `% no paths.` |
| `ps<TAB>aux` | `% one token only, no arguments.` |
| `ps${IFS}aux`, `id;ls`, `$(ls)` | `% unknown command` (taken literally — no expansion) |

Nothing expands, nothing concatenates, nothing resolves by path. So the solution has to live
*inside* one of the thirteen allowed programs.

---

## 3. What is running

```
> pstree
entrypoint.sh─┬─6*[collector]
              ├─sleep
              └─socat─┬─socat───jail
                      └─socat───jail───pstree
```

Six `collector` processes. `ps` only shows our own tty, `w` shows no users, `hostname` is a
container ID. Running `pstree` 150 times in a row revealed no short-lived process, so the
`sleep` loop in the entrypoint is not hiding anything either.

---

## 4. Driving curses tools over a socket

`htop` and `top` are full-screen curses programs, so raw `nc` output is unreadable. The fix:
send keystrokes over a raw socket and feed the replies into the **`pyte`** terminal emulator to
get a clean screen dump after each key.

Two things mattered enormously:

- **Arrow keys must be sent in application mode**: `ESC O B` / `ESC O C`. The usual
  `ESC [ B` / `ESC [ C` are silently ignored.
- **Each escape sequence needs its own write, with a pause after it.** Three right-arrows sent in
  a single write moved the cursor one step — the program coalesced them.

`btop` is unusable here: `ERROR: Failed to get size of terminal!`

---

## 5. htop: mostly dead ends, one pointer

htop shows the collectors as `/opt/collector/collector`, owned by `ctf` (our own uid), PIDs 9–14
on the first instance.

| htop key | Feature | Result |
|---|---|---|
| `e` | Environment | Only `HOME`, `LANG`, `PATH=/usr/bin`, `TERM` — on all six |
| `x` | File locks | "No locks have been found" on all six |
| `l` | Open files | `Could not execute 'lsof'` |
| `s` | Syscall trace | `Could not execute 'strace'` |
| → scroll | Full command line | No arguments on any collector |

Then: add columns through `F2` → Screens → Available Columns. **One differs:**

```
CWD                       EXE                 PID USER
/                         collector             9 ctf
/                         collector            10 ctf
/var/lib/collector        collector            11 ctf
/                         collector            12 ctf
/                         collector            13 ctf
/                         collector            14 ctf
```

One collector has its working directory in `/var/lib/collector`. Every other column tried —
PGRP, SID, TTY, NLWP, scheduler, RCHAR/WCHAR, syscall counts, cgroup, OOM, I/O priority, security
attribute, container — was identical across all six.

htop had nothing more to give: without `lsof` it cannot list file descriptors. But it had
singled out *which* process to look at.

---

## 6. `top`'s Inspect feature

`top` has an Inspect mode bound to `Y`. Its entries are defined in top's **rcfile**, which means
**whoever builds the image controls what they do** — they can read arbitrary per-PID files or run
arbitrary commands. That is the intended mechanism.

Pressing `Y` and entering a PID shows custom entries:

```
Inspection Pause at: pid 11, running collector
Use:  left/right then <Enter> to select an option; 'q' or <Esc> to end !
Options:  NUMA  State  Env  Held
```

`Held` matches the challenge wording ("figure out what it's holding").

**`State`** (one right-arrow, Enter) fails with "No such file or directory" on five collectors,
and works only on the one whose cwd is `/var/lib/collector`:

```
State: 1-1 lines,  1-80 columns, 62 bytes read
{"shard":"03","delegate":14,"sealed":true,"epoch":1794610961}
```

**`Held`** (three right-arrows, Enter) fails the same way on every collector *except* the
delegate named in that state file:

```
Inspection View at pid: 14, running collector.  Locating:  N/A
Held: 1-1 lines,  1-80 columns, 84 bytes read
{"shard":"03","token":"csaw{st1ll_0p3n_0n_thr33}","updated":"2026-08-14T22:11:04
```

Going by the flag text and "shard 03", the delegate presumably keeps the shard file open on
**file descriptor 3** and `Held` reads `/proc/<pid>/fd/3`. The rcfile was not readable, so the
exact path is an inference.

---

## 7. Checking it is not another decoy

- `Held` returns "No such file or directory" on the other five collectors, so there is exactly
  one candidate.
- The chain is internally consistent: odd cwd → `State` → `delegate` → `Held`, with `shard 03` at
  both ends.
- A **second instance** (collectors at PIDs 10–15, state on 12, delegate 15) returned the same
  flag. So the flag is static and the PIDs must be *discovered*, not hardcoded — which the solver
  does.

---

## 8. Solver

Needs `pip install pyte`. It lists the collectors from `top`, tries `State` on each until one
returns JSON, then reads `Held` on the named delegate.

```
$ python3 solve.py 10.0.219.164 1337
[*] collectors: [10, 11, 12, 13, 14, 15]
[-] pid 10: no state
[-] pid 11: no state
[+] pid 12 State: {'shard': '03', 'delegate': 15, 'sealed': True, 'epoch': 1794612565}
[+] pid 15 Held: {"shard":"03","token":"csaw{st1ll_0p3n_0n_thr33}","updated":"2026-08-14T22:11:04
[+] FLAG: csaw{st1ll_0p3n_0n_thr33}
```

It takes about a minute, because each keypress needs roughly a second to register. With shorter
delays the keys are dropped and every view comes back empty.

```python
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
```

---

## Flag

```
csaw{st1ll_0p3n_0n_thr33}
```

---

## Takeaways

- **With a tool whitelist, enumerate every interactive feature of every allowed tool.** `top`'s
  `Y` Inspect entries are author-controlled and can read arbitrary per-PID files or run commands
  — a genuinely underappreciated feature in a monitoring jail.
- **A tool's limits can still point the way.** htop cannot list file descriptors without `lsof`,
  but its CWD column singled out the right process out of six identical ones.
- **For curses tools over a socket:** use a terminal emulator (`pyte`), send application-mode
  arrow keys, one keypress per write, and wait between keys.
- **Prove the jail is closed before trying to escape it.** Ten minutes of systematic probing
  ruled out expansion, path resolution and concatenation, and redirected the effort to where the
  answer actually was.
- **Test against a second instance.** Different PIDs with the same flag proves the flag is static
  and forces the solver to discover PIDs rather than hardcode them.
