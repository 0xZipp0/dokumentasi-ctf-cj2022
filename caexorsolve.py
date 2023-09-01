from base64 import b64decode
from string import ascii_uppercase, ascii_lowercase

def decrypt(msg, key):
    encoded = ""

    for i in msg:
        if i.isalpha():
            if i.islower():
                encoded += ascii_lowercase[(ascii_lowercases.find(i) - key) % 26]
            else:
                encoded += ascii_uppercase[(ascii_uppercases.find(i) - key) % 26]
        else:
            encoded += i

    return encoded
enc = b64decode('eXR6Ymp2cWlmbGFlY3ZHek97ZXp1SnN4R0BtenNqcEBKS1J8fVJHU0NHC1Ym')
a = ''
for i in range(0,len(enc)):
    a += (chr(i^enc[i]))
print(decrypt(a,22))