from Crypto.Util.number import bytes_to_long, getPrime

flag = open("flag.txt", "rb").read()

p = getPrime(256)
q = getPrime(256)
n = p*q

e = 0x10001

m = bytes_to_long(flag)
c = pow(m,e,n)

with open("flag.enc", "wb") as f:
    f.write(f'n = {n}\nc = {c}\n')
    f.close()
    