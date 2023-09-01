hitam = open('hitam.jpg', 'rb').read()
binflag = ''.join(['1' if hitam == open(f'{i}.jpg', 'rb').read() else '0' for i in range(296)])
flag = ''.join([chr(int(binflag[i:i+8], 2)) for i in range(0, len(binflag), 8)])

print(flag)