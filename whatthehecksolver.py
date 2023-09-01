from PIL import Image
from binascii import unhexlify

flag = ''
for i in range(1, 13):
    rgb_color = Image.open(f'warna {i}.png').getpixel((100, 100))
    hex_color = "{:02x}{:02x}{:02x}".format(*rgb_color)
    flag += unhexlify(hex_color).decode('utf-8')
print(flag)