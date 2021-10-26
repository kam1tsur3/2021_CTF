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


My exploit code is [solve.py](https://github.com/kam1tsur3/2021_CTF/blob/master/asis/pwn/strvec/solve.py).

## Reference

twitter: @kam1tsur3
