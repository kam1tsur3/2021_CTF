#!/usr/bin/python3
check = [182, 199, 159, 225, 210, 6, 246, 8, 172, 245, 6, 246, 8, 245, 199, 154, 225, 245, 182, 245, 165, 225, 245, 7, 237, 246, 7, 43, 246, 8, 248, 215]

def value(c):
	inp = [0]*4
	val = c
	inp[0] = (c & 0x3)
	inp[1] = ((c >> 2) & 0x3)
	inp[2] = ((c >> 4) & 0x3)
	inp[3] = ((c >> 6) & 0x3)
	for i in range(4):
		if inp[i] == 0x0:
			val = ((val >> 3) | (val << 5)) & 0xff
		elif inp[i] == 0x1:
			val = ((val >> 6) | (val << 2)) & 0xff
		elif inp[i] == 0x2:
			val = (val + 0x37) & 0xff
		elif inp[i] == 0x3:
			val = val ^ 55
	return val

d = {}
for c in range(0x20, 0x80):
	if value(c) in d:
		print("duplicate="+d[value(c)]+" with "+chr(c))
	d[value(c)]	= chr(c)

flag = ""
for k in check:
	flag += d[k]

print(flag)
