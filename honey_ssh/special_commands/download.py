import hashlib
from datetime import datetime

import requests


def special_command(args):
    print(args)
    r = requests.get(args[0])
    print('/tmp/malware/' + datetime.now().strftime("%d-%m-%Y-%H-%M-%S") + "@" + args[0].split('/')[-1] + "@" + args[1])
    try:
        with open('/tmp/malware/' + datetime.now().strftime("%d-%m-%Y-%H-%M-%S") + args[0].split('/')[-1] + "@" + args[1], 'wb') as f:
            file_sha1 = hashlib.sha1(r.content)
            file_md5 = hashlib.md5(r.content)
            file_sha256 = hashlib.sha256(r.content)
            print(file_sha1.hexdigest())
            print(file_md5.hexdigest())
            print(file_sha256.hexdigest())
            f.write(r.content)
    except Exception as e:
        import traceback
        traceback.print_exc()
    return "\r\n"
