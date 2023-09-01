enc = ', \xEF S \xF2 \xED F \xEE \xED \x1C 9 5 - \xFF \xED @ \x11? P \xDO 8 3 \xF9 6X \xCD \xF8 ; 3 6 G 4 8 F \eX10 E W \xF9 \xED 7 F 8 F \\'.split('')
key = '7h1s_1s_n0t_th3_r3al_fl4g_d0nt_subm17_h3h3!'
flag = ''

for i in range(43):
    enc_code = ord(enc[i])
    key_code = ord(key[i])
    result_code = None

    if enc_code > 126:
        enc_code = 256 - enc_code

    if i % 3 == 0:
        result_code = enc_code + key_code
    elif i % 3 == 1:
        result_code = key_code - enc_code
    elif i % 3 == 2:
        result_code = enc_code ^ key_code

    if result_code > 126:
        result_code = key_code - enc_code
    flag += chr(result_code)
    
print(flag)
