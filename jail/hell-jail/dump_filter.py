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
