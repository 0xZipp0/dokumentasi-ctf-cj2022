from binascii import unhexlify

def big_edian(little_endian):
    return ''.join(little_endian[i:i+2] for i in range(len(little_endian), -1, -2))

o = '6371787c686e7269'
p = '785d6c65677b7a60'
q = '5345697b4f436269'
r = '5177616a607b4651'
s = '435141476f731flc'
t = '4e4b'

enc = unhexlify(big_edian(t + s + r + q + p + o))
for i in range(len(enc)):
    print(chr(enc[i]^(i+10)),end='')