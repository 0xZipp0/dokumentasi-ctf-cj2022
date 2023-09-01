import telnetlib

host = '103.13.207.182'
port = 30002

tn = telnetlib.Telnet(host, port)

while True:
    data = tn.read_util(b'=>')
    decoded = data.decode('utf-8')

    if 'cyber' in decoded:
        print(decoded)
        break

        calculation = eval(decoded.split('\n')[-1].strip('=>'))
        tn.write((str(calculation) + '\n').encode('utf-8'))

tn.close()