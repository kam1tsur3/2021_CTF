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
My exploit code is [solve.py](https://github.com/kam1tsur3/2021_CTF/blob/master/asis/pwn/just_pwn_it/solve.py).

## Reference

twitter: @kam1tsur3
