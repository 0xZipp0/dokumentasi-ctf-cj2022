from Crypto.Util.number import long_to_bytes
from math import isqrt

n = 3422897771005790672746023876402597 #potongan n.
c = 6334095164939357400059814475407466 #potongan c.

e = 65537
p = isqrt(n)

phi = n - p
d = pow(e, -1, phi)
pt = long_to_bytes(pow(c, d, n))
print(pt)