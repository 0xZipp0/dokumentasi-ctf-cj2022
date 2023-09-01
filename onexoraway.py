#!/usr/bin/env python3

from random import randint
from base64 import b64decode as b64e

def encrypt(message, key):
    return ''.join(chr(ord(i) ^ key) for i in message)

def fwrite(fname, message):
    with open(fname, 'w') as w:
        w.write(message)
        w.close()

    return True

def main():
    f = open('flag.txt').read()
    k = randint(1, 256)

    enc = encrypt(f, k)
    enc = b64e(enc.encode()).decode()

    fwrite('flag.enc', enc)

if __name__ == '__main__':
    main()

