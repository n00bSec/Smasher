# Smasher on HackTheBox (Partial)

This box got retired before I found time to get back to it. :( So this writeup is only on the first part.

# Part 1 - Smash and ROP for Initial shell

To breakdown of my usual attempts at HackTheBox so far:

	1. Recon - Learn the Target, Enumerate What You Can Do
	2. Research
	3. Check for Vulnerability
	4. If 3 isn't good enough, goto 2
	5. Exploit
	6. Get Shell/Credentials/Token for Access
	7. Look for flag
	8. Goto 1 if challenge not over.

Or that's at least how I plan to do things. On most boxes you should really be doing some kind
of recon the whole time, but in this case, the steps along are apparently meant to be easy to find,
difficult to exploit.

## Recon
Smasher's IP address looks to be `10.10.10.89`, so for convenience I like to add that kind of thing
to my `/etc/hosts` file, in a new line at the end.

```
...
10.10.10.89		smasher.htb
```

So now any interactions with this box can be done by referring to it as `smasher.htb`.

With that out of the way, the first step in approaching any kind of box like this
is to do some reconnaissence. My typical first kind of recon comes in the form of
an `nmap` scan, with additional scripts to .

```
# In a working directory for working on Smasher...

#Store scan results for later
mkdir nmap 

# Checkout `man nmap`, and use / to search for different flags used here.
sudo nmap -A -T5 -sS -sV -oA nmap/fullscan smasher.htb

```

The results are rather straightforward to read. The machine is running Ubuntu. There's two services:

- SSH Server on Port 22. Easy login later? Or maybe it's old enough for an interesting vuln to be used?
- HTTP Server named `shenfeng tiny-web-server` on Port 1111. Definitely stands out as unusual, probably the target.

We can check out the HTTP Server by visiting `smasher.htb:1111` in a browser or by using curl.
What we see is a directory listing with an index.html listed.

	Here in retracing, the server seems stuck a lot. So someone keeps breaking it, and a reset needed to be requested each time. :')
	Gotta love finicky and buggy servers.

## Research
After navigating around any assets, you might find that there's nothing really interesting to interact with,
and that the intended vulnerability has more to do with the particular server software. That's where more
recon earlier could have came in.

Searching up `shenfeng tiny-web-server` on Google (different results on DuckDuckGo?) you get two excellent results
worth digging into. The first is the Github 
[project](https://www.google.com/url?sa=t&rct=j&q=&esrc=s&source=web&cd=1&cad=rja&uact=8&ved=2ahUKEwiOhoyOieHdAhXKrFkKHZNTDN0QFjAAegQIDBAB&url=https%3A%2F%2Fgithub.com%2Fshenfeng%2Ftiny-web-server&usg=AOvVaw3ErUcF4VVjHWGYgE4L8w3X) 
from which this server is based, and the second
is a [writeup](https://www.google.com/url?sa=t&rct=j&q=&esrc=s&source=web&cd=4&cad=rja&uact=8&ved=2ahUKEwiOhoyOieHdAhXKrFkKHZNTDN0QFjADegQIChAB&url=http%3A%2F%2Fwww.surfingthecyber.com%2F2017%2F11%2F10%2Ftiny-web-server-buffer-overflow-discovery-and-poc.html&usg=AOvVaw2tIuZ9kG9HXM_UdoIlJELk)
on the discovery of a buffer overflow, with a crashing proof of concept.

From here I read the blog post and a good deal of the server source code.
The blog post really is where I'd recommend getting going on understanding how to write your exploit.

The server is likely someone's old C programming project with a stack buffer overflow in handling
URL encoding. That's to say we can trigger a buggy URL decoding routine, write up the stack fully controllable
data by URL encoding it, and take control of the program counter a nearly arbitrary number of times through
Return Oriented Programming.

I began by making an HTTP request with my web browser, and copying the contents sent into a Python string.
I like writing exploits in Python because Pwntools is so handy a library and I have exploit templates
that remove the tedium from transitioning from developing a local exploit to remote.
This time I also had the additional benefit of tweaking data, like the URL parameter.

I noticed that the URL-handling in the server is vulnerable to a directory traversal attack, 
and this just so happens to be the way we can get the binary on the server for exploiting.
This vulnerability could actually be used to leak data from any file we can get the relative path to,
but the server doesn't have rights to many files one ought to care about, and there's a size limit
on the data the server can output.

Having a copy of the binary dramatically simplifies remote exploitation because
it gives all of the valuable offsets to code and data within as its loaded into
the remote process's address space.

See `getremotebinary.py`. `data` is the HTTP request hex encoded for easy sending
over TCP, giving really precise control over the resource path sent. Doesn't hurt
to steal the libc too when possible.

With the binary available and an idea of where the vulnerability was, I copied some parameters into
my usual CTF binary exploit starting script and got to downloading, crashing, and debugging.

## Exploitation

Once the binary was downloaded (`remote_tiny`), I copied my usual exploit template,
filled in some info, and got the local server successfully attached under GDB.
One should notice that there's an explicit lack of memory mitigations here,
to make things easier. In radare2:
```
:> iI
...
bintype  elf
canary   false
machine  AMD x86-64 architecture
nx       false
os       linux
pic      false
relro    partial
stripped false
...
```

So where the blog post explains the stack buffer overflow vulnerability in
the resource path, we can confirm that not only can we overwrite the return
address on the stack with enough data, we can also write whatever bytes we
like because of URL decoding.

So, I broke the attack into two stages to get the shell purely through ROP.
My notes say I tried shellcode, and that wasn't working, so I guess ROP
turned out easier for me here.

## Stage 1

Stage 1 is all about leaking addresses from the GOT to find the libc
in the address space. This allowed me to search up/download the libc
binary and/or run tools like `one_gadget` over it to find a `magic gadget`.

Because `tiny` forks for each connection, we happen to rather consistently
connect to file descriptor `4` with our socket when we make a TCP connection.

The gadgets I chose essentially performs a `write(4, &read, 0x8)` to read back
the address of `write()` in libc, and then an additional `write(4, &write, 0x8)`.

From there we can deduce the base of libc in memory. :)

## Stage 2

Next I used the data gathered to finish getting a shell.

There's some leftover code from my attempts at calling `system`,
and `/bin/sh` shellcode, but what followed was another ROP chain
to:
- `dup2(4, 0)`: feed our socket descriptor into standard input
- `dup2(4, 1)`: feed our socket into standard output 
- `dup2(4, 2)`: feed our socket into stderr
- magic gadget! Get an instant shell with a gagdet from `one_gadget`.

Our magic gadget:
```bash
$ one_gadget libc6_2.2
...
0xf02a4 execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL
...
```

Some padding was added to meet the stack constraints.

# Part 2 - Beware Crypto: Oracle Padding Attack?

So after smashing the stack, and ROPping to a shell, some more recon
followed that allowed me to see the following service listening:
`smasher    720  0.0  0.1  24364  1684 ?        S    06:03   0:00 socat TCP-LISTEN:1337,reuseaddr,fork,bind=127.0.0.1 EXEC:/usr/bin/python /home/smasher/crackme.py`

It's reachable by `nc localhost 1337`.

```
[*] Welcome to AES Checker! (type 'exit' to quit)
[!] Crack this one: irRmWB7oJSMbtBC4QuoB13DC08NI06MbcWEOc94q0OXPbfgRm+l9xHkPQ7r7NdFjo6hSo6togqLYITGGpPsXdg==
Insert ciphertext:
```

And here, it looks a lot like a Padding Oracle Attack, something which I had not
managed to adequately learn in time before I had to break from this box. :|
Learning this attack and overcoming my shortcomings in crypto 
will be how I'll have to redeem myself on this, when I have time again...

