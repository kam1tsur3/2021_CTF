#!/usr/bin/python3
from pwn import *
import sys

#config
context(os='linux', arch='i386')
context.log_level = 'debug'

FILE_NAME = "./rflag"
HOST = "misc.cakectf.com"
PORT = 10023

if len(sys.argv) > 1 and sys.argv[1] == 'r':
	conn = remote(HOST, PORT)
else:
	conn = process(FILE_NAME)

def exploit():
	sig = ["[13579bdf]","[2367abef]","[4567cdef]","[89abcdef]"]
	flag = [0 for x in range(0,32)]	
	flag_s = ""
	for i in range(0,4):
		conn.sendlineafter(":",sig[i])	
		conn.recvuntil(": [")
		arr = conn.recvuntil("]")[:-1].split(b",")
		for x in arr:
			flag[int(x)] |= (1 << i)
	for c in flag:
		flag_s += "%x"%c
	print(flag_s)
	conn.sendlineafter("?\n", flag_s)
	conn.interactive()	

if __name__ == "__main__":
	exploit()	
