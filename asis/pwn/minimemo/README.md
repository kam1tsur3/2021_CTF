# minimemo
I solved kernel exploit challenge for the first time.  
I'm so glad, thanks to author @ptrYudai.  
He always give us good tasks.  

## TLDR
### Vulnerability
* buffer overflow on kernel heap
### How to attack
* unlink attack
* overwrite modprobe\_path

## Challenge
### Description
Linux kernel security function
* KASLR  : Enable
* KPTI   : Disable
* SMEP   : Disable
* SMAP   : Disable

Linux 5.14.3
### Exploit 
I solved this challenges with brute force attack(3bit + a).  
So my solution was not smart.  

We can overwrite "fd" member of struct notelist\_t, but with value of "id" member.  
When the most lowest bytes of "id" is proper, we cana link user land data to linked list, because SMAP is disable.  
If it can be, we can get the address of the kernel heap address and the kernel module addresss, and do AAW via user land data.  
But we cannot get the kernel base address.  

See around the kernel module address, there are some addresses which based on the kernel base address.  
* memory dump around global variable top(kernel module address = 0xffffffffc006b000)
``
wndbg> x/20gx 0xffffffffc006b000+0x2100
0xffffffffc006d100:     0x0000000000000000      0x0000000000000000
0xffffffffc006d110:     0x0000000000000000      0xffffffffc006d100  <- top.fd
0xffffffffc006d120:     0xffffffffc006d100      0x0000000000000000  <--- top.bk
0xffffffffc006d130:     0x0000000000000000      0x0000000000000000
0xffffffffc006d140:     0x0000000000000000      0xffffffffb72a9e80  <- kernel base address + ????
0xffffffffc006d150:     0xffffffffb72a9e80      0x6f6d656d696e696d  <--- kernel base address + ????
0xffffffffc006d160:     0x0000000000000000      0x0000000000000000
0xffffffffc006d170:     0x0000000000000000      0x0000000000000000
0xffffffffc006d180:     0x0000000000000000      0x0000000000000000
0xffffffffc006d190:     0xffff922e81339600      0xffff922e811191e0
```

I overwrote the lowest 3 bytes of these address with offset of modprobe\_path. To success this attack, we need to conqure 3bit brute force(It is caused by KASLR).  

My exploit code is [k\_exp.py](https://github.com/kam1tsur3/2021_CTF/blob/master/asis/pwn/minimemo/exploit/k_exp.c).

## Reference

twitter: @kam1tsur3
