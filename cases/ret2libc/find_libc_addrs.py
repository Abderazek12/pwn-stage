from pwn import *

libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
print("system      :", hex(libc.symbols['system']))
print("exit        :", hex(libc.symbols['exit']))
print("/bin/sh     :", hex(next(libc.search(b'/bin/sh'))))
