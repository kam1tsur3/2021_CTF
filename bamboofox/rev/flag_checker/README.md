# Flag Checker
50pt

## Challenge
We have 3 verilog files.  
It is a simple reversing challenge.  
The original string is encoded each character.  
Read source codes, write solvers.  
Nothing to say more.  

### Solution
The result of encoding is sometimes duplicated.  
For example, "1" and "\_" have same result.  
So my solver say, the flag is "flag{v3ry_v3r_log_f_dg_ch3ck3r!}".  
But, we have to change some character with which have same result.
Correct flag is │flag{v3ry_v3rllog_f14g_ch3ck3r!}.  
My solver is [here](https://github.com/kam1tsur3/2021_CTF/blob/master/bamboofox/rev/flag_checker/solve.py).

## Reference
twitter: @kam1tsur3
