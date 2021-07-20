#!/usr/bin/python3
from pwn import *
import sys

#config
context(os='linux', arch='i386')
context.log_level = 'debug'

c_array = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ{}0123456789_!$-.<=>?@*"

def exploit():
	flag = ""
	base = ["gcc", "./cpp.c"]
	for i in range(4, 26):
	#for i in range(4,5):
		options = [] + base
		r = 0x100 - (i+1)
		for j in range(8):
			if(r >> j & 1):
				arg = "-DPRE"+str(j)
				options.append(arg)

		for c in c_array:
			arg  = ["-DFLG"+str(i)+"="+str(ord(c))]
			conn = process(options+arg)		
			while True:
				status = conn.poll()
				if status != None:
					break
			if status != 1:
				flag += c
				flagment = "-DFLG"+str(i)+"="+str(ord(c))
				base.append(flagment)
				conn.close()
				break
			conn.close()
		print("Flag:" +flag)
	print(flag)

if __name__ == "__main__":
	exploit()	
