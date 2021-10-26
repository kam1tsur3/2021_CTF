#!/bin/bash
cd exploit
gcc -o exploit -masm=intel -static k_exp.c
#gcc -o exploit -masm=intel  k_exp.c -pthread -no-pie -fno-PIE
# for local
cd ..
cp ./exploit/exploit ./mnt/
cd ./mnt
find . | cpio -H newc --owner root -o > ../rootfs.cpio
cd ..
# for remote
strip ./exploit/exploit
#upx ./exploit/exploit
gzip ./exploit/exploit -c > ./solver.gz
base64 ./solver.gz > ./solver.gz.enc
