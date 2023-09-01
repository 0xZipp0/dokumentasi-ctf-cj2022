from base64 import b64decode
from pwn import xor
a = b64decode(open('flag.enc','r').read())
for i in range(0,256):
    if "cyberwar" in xor(a,i).decode():
        print(xor(a,i).decode())
        break
