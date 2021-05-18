gdb -ex 'target remote localhost:8888' -ex 'print asm-demangle' \
	-ex 'print 0x555555554000' -ex 'print 0x55555555b000'
