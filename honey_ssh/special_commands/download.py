import hashlib
from datetime import datetime
import requests

from honey_log.honeypot_event import HoneyPotFileEventContent


def special_command(args):
    downloaded_file = requests.get(args[0]).content
    try:
        with open('/tmp/malware/' + datetime.now().strftime("%d-%m-%Y-%H-%M-%S") + args[0].split('/')[-1] + "@" + args[1], 'wb') as saved_file:
            file_sha1 = hashlib.sha1(downloaded_file)
            file_md5 = hashlib.md5(downloaded_file)
            file_sha256 = hashlib.sha256(downloaded_file)
            args[2].report_event("file", HoneyPotFileEventContent(args[1], "SSH", args[0].split('/')[-1], file_md5, file_sha1, file_sha256, len(downloaded_file)))
            saved_file.write(downloaded_file)
    except Exception as e:
        import traceback
        traceback.print_exc()
    return "\r\n"
