# Not Beginner's stack 

## TLDR
* BOF 
* SOP(Sigreturn Oriented Program)

## Challenge
### Description
Result of file command
* Arch    : x86-64
* Library : Statically linked (No library)
* Symbol  : Not stripped

Result of checksec
* RELRO  : No RELRO (No library)
* Canary : Disable
* NX     : Enable
* PIE    : Disable

In this challenge,  "call" and "ret" instruction is not used.  
Intead, 2 macros is defineded in main.S.  
```
%macro call 1
;; __stack_shadow[__stack_depth++] = return_address;
  mov ecx, [__stack_depth]
  mov qword [__stack_shadow + rcx * 8], %%return_address
  inc dword [__stack_depth]
;; goto function
  jmp %1
  %%return_address:
%endmacro

%macro ret 0
;; goto __stack_shadow[--__stack_depth];
  dec dword [__stack_depth]
  mov ecx, [__stack_depth]
  jmp qword [__stack_shadow + rcx * 8]
%endmacro
```
Original subroutine is implemented.  
Return address is stored on bss area, not on stack.  

### Exploit 
This challenge has a simple buffer overflow vulnerabirity.  
```
notvuln:
;; char buf[0x100];
  enter 0x100, 0
;; vuln();
  call vuln
;; write(1, "Data: ", 6);
  mov edx, 6
  mov esi, msg_data
  xor edi, edi
  inc edi
  call write
;; read(0, buf, 0x100);
  mov edx, 0x100
  lea rsi, [rbp-0x100]
  xor edi, edi
  call read
;; return 0;
  xor eax, eax
  ret

vuln:
;; char buf[0x100];
  enter 0x100, 0
;; write(1, "Data: ", 6);
  mov edx, 6
  mov esi, msg_data
  xor edi, edi
  inc edi
  call write
;; read(0, buf, 0x1000);
  mov edx, 0x1000               ; [!] vulnerability
  lea rsi, [rbp-0x100]
  xor edi, edi
  call read
;; return;
  leave
  ret
```
read() is called at 2 times.  
First read() in vuln() can overwrite old\_rbp stored on stack.  
Second read() in notvuln() can trigger AAW because read buffer is based rbp value.  
I overwrote \_\_stack\_shadow to control RIP.

I didn't notice that we could execute shellcode :(   
Instead, I used Sigreturn Oriented Program to get shell.  

My exploit code is [solve.py](https://github.com/kam1tsur3/2021_CTF/blob/master/zer0pts/pwn/not_beginners_stack/solve.py).

## Reference
Sigreturn Oriented Programing(In Japanese)
* http://inaz2.hatenablog.com/entry/2014/07/30/021123

twitter: @kam1tsur3
