# Calc.exe Online 
50pt   
This is first time to make a writeup for web challenges :3   

## Challenge
Here is a part of the source code.  

```php
<?php
error_reporting(0);
isset($_GET['source']) && die(highlight_file(__FILE__));

function is_safe($query)
{
    $query = strtolower($query);
    preg_match_all("/([a-z_]+)/", $query, $words);
    $words = $words[0];
    $good = ['abs', 'acos', 'acosh', 'asin', 'asinh', 'atan2', 'atan', 'atanh', 'base_convert', 'bindec', 'ceil', 'cos', 'cosh', 'decbin', 'dechex', 'decoct', 'deg2rad', 'exp', 'floor', 'fmod', 'getrandmax', 'hexdec', 'hypot', 'is_finite', 'is_infinite', 'is_nan', 'lcg_value', 'log10', 'log', 'max', 'min', 'mt_getrandmax', 'mt_rand', 'octdec', 'pi', 'pow', 'rad2deg', 'rand', 'round', 'sin', 'sinh', 'sqrt', 'srand', 'tan', 'tanh', 'ncr', 'npr', 'number_format'];
    $accept_chars = '_abcdefghijklmnopqrstuvwxyz0123456789.!^&|+-*/%()[],';
    $accept_chars = str_split($accept_chars);
    $bad = '';

	for ($i = 0; $i < count($words); $i++) {
        if (strlen($words[$i]) && array_search($words[$i], $good) === false) {
            $bad .= $words[$i] . " ";
        }
    }

    for ($i = 0; $i < strlen($query); $i++) {
        if (array_search($query[$i], $accept_chars) === false) {
            $bad .= $query[$i] . " ";
        }
    }
    return $bad;
}

function safe_eval($code)
{
    if (strlen($code) > 1024) return "Expression too long.";
    $code = strtolower($code);
    $bad = is_safe($code);
    $res = '';
    if (strlen(str_replace(' ', '', $bad)))
        $res = "I don't like this: " . $bad;
    else {
        eval('$res=' . $code . ";");
	}
    return $res;
}
?>
...
...
    <div class="container" style="margin-top: 3em; margin-bottom: 3em;">
        <div class="columns is-centered">
            <div class="column is-8-tablet is-8-desktop is-5-widescreen">
                <form>
                    <div class="field">
                        <div class="control">
                            <input class="input is-large" placeholder="1+1" type="text" name="expression" value="<?= $_GET['expression'] ?? '' ?>" />
                        </div>
                    </div>
                </form>
            </div>
        </div>
        <div class="columns is-centered">
            <?php if (isset($_GET['expression'])) : ?>
                <div class="card column is-8-tablet is-8-desktop is-5-widescreen">
                    <div class="card-content">
                        = <?= @safe_eval($_GET['expression']) ?>
                    </div>
                </div>
            <?php endif ?>
            <a href="/?source"></a>
        </div>
    </div>
...
...
```

It is a simple php challenge.
We want to pass good string to eval() in safe\_eval().  

### Solution
First, I found that it is valid and executed.
```
# input => result
abs[0] => a 
abs[0].abs[2] => as
```
Because "abs" is defined as a element of $good. It can bypass the filter.

Next, I wanted to execute phpinfo().
After many trial, I found that the following code is valid.
```
(hypot[2].hypot[0].hypot[2].min[1].min[2].floor[0].floor[2])()
```
Good. And, I executed system("ls") as same as phpinfo().  
But, flag was not found.  
So I tried to execute system("ls /"), but cannot express "/" because $good has not strings that have "/".  

I thought how to express any character and found that 
```
(cos[0].tanh[3].ncr[2])(65) => chr(65) => A
```
Now I can execute any code with chr(). 

Finally, I executed system("ls /") ,found the file name of flag was "/flag\_a2647e5eb8e9e767fe298aa012a49b50" and did system("cat /flag\_a2647e5eb8e9e767fe298aa012a49b50").

Be careful that the length of input must be less than 1025.  
If your input is too long, you'll have to find another expressiong of input.

My solver is [here](https://github.com/kam1tsur3/2021_CTF/blob/master/bamboofox/web/calc_exe_online/solve.py).

## Reference
twitter: @kam1tsur3
