#!/usr/bin/env python3
from pwn import *
from sys import argv
binary = ELF()
libc = ELF()
if len(argv) >= 2 and argv[1] == '-r':
  p = remote()
else:
  p = binary.process(env={})

sl = lambda x, r="" : \
  p.sendlineafter(r, x) if r else p.sendline(x)

# for lazy heap note challs lol
def menu(*args):
#  p.recvuntil('option')
  for i in args:
    sl(str(i).encode(), b':')

pause()
p.interactive()

