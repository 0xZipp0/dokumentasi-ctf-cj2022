#a = [63, 78, 60, 66, 76, 72, 67, 75, 7A, 60, 65, 79, 7F, 76,7E, 3B, 7E, 28, 2B, 7A, 78, 4A, 22, 66, 47, 72, 51, 66]
b = 'cx`fvrguz`ey.v~;~(+zxJ"fGrQf'
for i in range(0,28):
    print(chr(i^ord(b[i])),end='')
