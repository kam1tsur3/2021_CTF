#!/bin/bash
cd exploit
gcc -o exploit -masm=intel -static -pthread k_exp.c
cd ..
cp ./exploit/exploit ./mnt/
cd ./mnt
find . | cpio -H newc --owner root -o > ../rootfs.cpio
cd ..
