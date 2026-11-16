# Hell Jail

| Event | Category | Points | Flag |
|---|---|---|---|
| CSAW CTF Final Round 2026 | Jail / Reverse | 500 | `csaw{uNC0v3rd_t#e_Dev1l$_0rDe&l__$uch_&_e^v1l_M0nst3r__t#aNk$_f0r_v1s1Tng}` |

> Welcome to hell, come on in, we eat what you feed with a devilish grin. But shadows creep and
> eyes may peer, so nothing's quite what it seems down here.
>
> Chant that spell hidden in `/flag`, which opens the door to get out of this hell. Port: 1337.

**TL;DR** — A seccomp jail that runs whatever ELF you feed it. It checks `TracerPid` and
**installs a different filter when it is being debugged**, so the filter `seccomp-tools` shows
you is a decoy. Force the anti-debug check to return "clean", dump the real filter at the
`prctl` call, and it turns out `openat` is allowed if the ignored `mode` argument hashes to a
magic constant. The hash is xor/add/rotate/multiply — all invertible. Invert it, write a
libc-free assembly payload, send it.

---

## 1. What the binary even is

```
$ strings hell-jail          # nothing useful
$ nm -D hell-jail            # no libc I/O imports
```

It makes raw syscalls, and every string is XORed with `0xA5` and written into `.bss` byte by
byte at runtime. `main` is 16 KB and is a bytecode VM. Reading that statically is a waste of
time — read its **syscalls** instead:

```
$ strace -f ./hell-jail hello
prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)  = 0
prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, {len=55, filter=0x7ffe5b3b3688}) = 0
execve("hello", ["hello"], ...)         = -1 ENOENT
```

Three lines answer the question: it installs a 55-instruction seccomp filter, then executes
`argv[1]`. The service on port 1337 "eats what you feed" — it takes a program from you and runs
it this way, with the flag at `/flag`.

---

## 2. Dump the filter — and fall for the decoy

```
$ seccomp-tools dump "./hell-jail x"
```

A whitelist: `read`, `write`, `close`, `fstat`, `lseek`, `mmap`, `mprotect`, `munmap`, `brk`,
`ioctl`, `readv`, `writev`, `execve`, `exit`, `exit_group`, a few runtime-startup calls — and no
`open` or `openat`. One syscall is allowed conditionally:

```
0033: if (A != pread64) goto KILL
      count >> 32 == 0, pos >> 32 == 0
0038: A = count
      A = rol32(A, 21) ^ 0xa5c3f00d
      A = A * 0xcc9e2d51 + 0x0badbeef
      A = ((A ^ 0x11223344) - 0x0badcafe) ^ 0xdeadc0de
0052: if (A != 0x230226d9) goto KILL
```

Inverting that gives `count = 0xf00dface`. The obvious reading: *the service passes an open fd
for the flag; `pread64` it with the magic count*. It is a complete, self-consistent, entirely
false story.

---

## 3. The tell: the payload only works while traced

A test payload calling `pread64(3, buf, 0xf00dface, 0)`:

```
$ strace -f ./hell-jail ./exp 3<fakeflag     # prints fakeflag
$ ./hell-jail ./exp 3<fakeflag
Bad system call (core dumped)
```

Same program, same input — different result depending only on whether something is watching.
That is "eyes may peer, nothing's quite what it seems".

The function at `0x11e1` opens `/proc/self/status` and reads `TracerPid:`. If a tracer is
attached it installs the decoy filter from step 2. The server runs untraced and installs a
different one.

> **The general lesson:** a seccomp filter observed under `ptrace` is only what the program chose
> to show a tracer. Any time a payload passes under `strace` and dies without it, suspect an
> anti-debug branch rather than your payload.

---

## 4. Dump the real filter

The filter constants are computed at runtime by a *second* small VM at `0x153e`, so they cannot
be carved out of the file. Two options: emulate both VMs with the tracer check forced to
"clean", or lie to the check and grab the filter at the `prctl` call. The second is far cheaper.

```python
# dump_filter.py — gdb -q --batch -x dump_filter.py
# Forces the TracerPid check to return 0, then captures the sock_fprog at PR_SET_SECCOMP.
import gdb, struct
for c in ("set pagination off", "set confirm off", "set disable-randomization on"):
    gdb.execute(c)
BASE = 0x555555554000                        # PIE base with ASLR off
gdb.execute("file ./hell-jail")
gdb.execute("break *%#x" % (BASE + 0x11e1))  # the TracerPid check
gdb.execute("run /bin/true")
gdb.execute("return (long)0")                # "nobody is tracing"
gdb.execute("catch syscall prctl")
for _ in range(20):
    gdb.execute("continue")
    orig = int(gdb.parse_and_eval("$orig_rax"))
    rdi  = int(gdb.parse_and_eval("$rdi"))
    rax  = int(gdb.parse_and_eval("$rax"))
    if orig == 157 and rdi == 22 and rax == -38:   # PR_SET_SECCOMP, at syscall entry
        inf  = gdb.inferiors()[0]
        prog = bytes(inf.read_memory(int(gdb.parse_and_eval("$rdx")), 16))
        n, ptr = struct.unpack("<H", prog[:2])[0], struct.unpack("<Q", prog[8:])[0]
        open("real_filter.bin", "wb").write(bytes(inf.read_memory(ptr, n * 8)))
        break
gdb.execute("kill")
```

```
$ seccomp-tools disasm real_filter.bin
```

Note the `rax == -38` check: `-ENOSYS` means we are at syscall *entry*, before the kernel has
copied the filter, so the pointer in `$rdx` is still valid user memory.

---

## 5. Read the real filter

Same whitelist. Different conditional tail:

```
0033: if (A != openat) goto KILL
0034: flags >> 32 == 0
0036: flags == 0                      ; exactly O_RDONLY
0038: mode >> 32 == 0
0040: A = mode
0041: A ^= 0x5a5a5a5a
0042: A *= 0x9e3779b1
0043: A += 0x1badc0de
0044: A = (A << 13) | (A >> 19)       ; rol32(A, 13)
0051: A ^= 0xa5a5a5a5
0052: if (A != 0x7665438e) goto KILL
0053: return ALLOW
```

`openat` is allowed if the flags are exactly `O_RDONLY` and the hash of `mode` equals
`0x7665438e`. **The path is never checked.**

The elegance: the kernel ignores `mode` entirely unless `O_CREAT` is set, and the filter has just
required `flags == 0`. So `mode` is a completely free 32-bit slot that affects nothing except the
seccomp decision. That is the "spell".

---

## 6. Invert the hash

XOR, add, rotate and multiplication by an **odd** number are all invertible mod 2³², so undo them
in reverse order. (The multiplier `0x9e3779b1` is odd, hence a unit mod 2³² — this is why BPF
argument "hashes" of this shape are never one-way.)

```python
# invert.py — recover the magic openat mode from the filter's hash constant.
M   = 0xffffffff
rol = lambda v, n: ((v << n) | (v >> (32 - n))) & M
ror = lambda v, n: rol(v, 32 - n)

t    = ror(0x7665438e ^ 0xa5a5a5a5, 13)
t    = (t - 0x1badc0de) & M
t    = t * pow(0x9e3779b1, -1, 1 << 32) & M
mode = t ^ 0x5a5a5a5a
print(hex(mode))                      # 0xf289daa3
```

---

## 7. The payload

It must be static and libc-free: ordinary program startup makes syscalls the filter kills.

```nasm
; open.asm — nasm -f elf64 open.asm -o open.o && ld -static -nostdlib open.o -o open_flag
BITS 64
default rel
section .text
global _start
_start:
    mov eax, 257            ; openat
    mov rdi, -100           ; AT_FDCWD
    lea rsi, [path]
    xor edx, edx            ; flags = O_RDONLY  (the filter requires exactly 0)
    mov r10d, 0xf289daa3    ; mode = the spell
    syscall
    mov r12, rax
.loop:
    xor eax, eax            ; read(fd, buf, 0x1000)
    mov rdi, r12
    lea rsi, [buf]
    mov edx, 0x1000
    syscall
    test rax, rax
    jle .done
    mov rdx, rax
    mov eax, 1              ; write(1, buf, n)
    mov edi, 1
    lea rsi, [buf]
    syscall
    jmp .loop
.done:
    mov eax, 60             ; exit(0)
    xor edi, edi
    syscall
path: db "/flag",0
section .bss
buf: resb 0x1000
```

### Test locally, untraced

Build a copy with `path` pointing at a test file and run it with **no tracer attached**:

```
$ ./hell-jail ./open_my
csawctf{local_openat_spell_ok}
$ ./hell-jail /bin/cat testfile        # control: ordinary openat, no magic mode
Bad system call (core dumped)
```

The payload gets through and an ordinary program does not — that is the proof you have the real
filter, not another decoy.

---

## 8. Send it

The service prints no banner and no prompt. Send the raw ELF, half-close the socket so it sees
EOF, then read:

```python
# send.py — ship the ELF to the jail service and read the flag back.
import socket
s = socket.create_connection(("10.0.219.67", 1337), timeout=10)
s.sendall(open("open_flag", "rb").read())
s.shutdown(socket.SHUT_WR)
out = b""
while (d := s.recv(4096)):
    out += d
print(out.decode())
```

```
csaw{uNC0v3rd_t#e_Dev1l$_0rDe&l__$uch_&_e^v1l_M0nst3r__t#aNk$_f0r_v1s1Tng}
```

---

## Flag

```
csaw{uNC0v3rd_t#e_Dev1l$_0rDe&l__$uch_&_e^v1l_M0nst3r__t#aNk$_f0r_v1s1Tng}
```

---

## Takeaways

- **A filter dumped under `ptrace` is a filter the program agreed to show you.** The decoy was
  complete and invertible, which is exactly what made it convincing.
- **"Works under strace, dies without it" is the signature of an anti-debug branch** — and a
  cheap thing to test deliberately rather than stumble into.
- **Forcing one return value beats emulating two VMs.** `return (long)0` at the check, plus a
  breakpoint at `prctl`, took minutes; reversing the constant-generating VM would have taken
  hours for the same bytes.
- **Syscall arguments the kernel ignores are free channels.** `mode` without `O_CREAT` is dead
  weight to the kernel and a perfect password slot to a filter author.
- **xor / add / rotate / odd-multiply chains are always invertible mod 2³².** They look like
  hashes in BPF disassembly but carry no one-wayness at all.

## Files

- [`dump_filter.py`](dump_filter.py) — GDB script that defeats the tracer check and dumps the real filter.
- [`invert.py`](invert.py) — recovers the magic `mode` value.
- [`open.asm`](open.asm) — the libc-free payload.
- [`send.py`](send.py) — delivers the ELF to the service.

## Tools

`strace`, `seccomp-tools`, GDB (batch scripting), `nasm` + `ld`.
