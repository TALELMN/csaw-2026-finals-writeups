# invert.py — recover the magic openat mode from the filter's hash constant.
M   = 0xffffffff
rol = lambda v, n: ((v << n) | (v >> (32 - n))) & M
ror = lambda v, n: rol(v, 32 - n)

t    = ror(0x7665438e ^ 0xa5a5a5a5, 13)
t    = (t - 0x1badc0de) & M
t    = t * pow(0x9e3779b1, -1, 1 << 32) & M
mode = t ^ 0x5a5a5a5a
print(hex(mode))                      # 0xf289daa3
