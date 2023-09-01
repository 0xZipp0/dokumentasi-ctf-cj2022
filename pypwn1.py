#!/usr/bin/env python2
import os, sys
import subprocess
from random import randint

try:
    secret = randint(0, 999999)
    key = input("[>] Insert key: ")
    if key == secret:
        print("[*] Correct!")
    else:
        print("[!] Wrong!")
except:
    print("[!] Wrong!")