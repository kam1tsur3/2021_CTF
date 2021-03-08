# OneShot

## Challenge
### Description
Result of file command
* Arch    : x86-64
* Library : Dynamically linked
* Symbol  : Not stripped

Result of checksec
* RELRO  : Partial RELRO
* Canary : Disable
* NX     : Enable
* PIE    : Disable

libc version: 2.31

We can allocate a chunk whose size is less than (4 * 0x100).  
And we can also write 4 bytes at chunk\[offset\] only once (offset is given by user input).

Do we really allocate and write only once???
### Exploit 
Return value of calloc() is not checked. It is vulnerable.  
In addition, offset given by user input is not check too. It is also vulnerable.  

If we give calloc() "-1", calloc() returns 0.  
So we can overwrite got area because PIE is disable.  

My exploit step is ...

#### make infinite loop  
Overwriting got_puts to the address of main.  

#### enable allocate chunks larger than limitation(> 4\*0x100)   
Overwriting got\_exit to the address of some gadget(only execute "ret;")

#### libc leak  
If we allocate some extra large chunks (For example 0x22000), chunks are always located just before the address of libc.  
By using this malloc(calloc) feature, we can also AAW for libc.  

In order to leak the address of libc,  
I wrote 4bytes at \_IO\_2\_1\_stdout+4, overwrote got\_setbuf to printf   
and call setup() (printf(stdout) was executed).
```
0x7ffff7fb76a0 <_IO_2_1_stdout_>:       0x00000000fbad2887      0x00007ffff7fb7723
0x7ffff7fb76b0 <_IO_2_1_stdout_+16>:    0x00007ffff7fb7723      0x00007ffff7fb7723
0x7ffff7fb76c0 <_IO_2_1_stdout_+32>:    0x00007ffff7fb7723      0x00007ffff7fb7723
0x7ffff7fb76d0 <_IO_2_1_stdout_+48>:    0x00007ffff7fb7723      0x00007ffff7fb7723
0x7ffff7fb76e0 <_IO_2_1_stdout_+64>:    0x00007ffff7fb7724      0x0000000000000000
```

#### one gadget rce  
Distributed libc has following one gadge RCE.
```
0xe6e79 execve("/bin/sh", rsi, rdx)
constraints:
  [rsi] == NULL || rsi == NULL
  [rdx] == NULL || rdx == NULL

```
The registers before calling scanf() in main() always satisfies the condition.  
So I overwrote got_scanf to one_gadget RCE.

My exploit code is [solve.py](https://github.com/kam1tsur3/2021_CTF/blob/master/zer0pts/pwn/oneshot/solve.py).

## Reference

twitter: @kam1tsur3
