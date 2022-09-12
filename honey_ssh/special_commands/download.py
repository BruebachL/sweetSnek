import hashlib
from datetime import datetime
import requests

from honey_log.honeypot_event import HoneyPotFileEventContent


def special_command(args):
    command_string, client_info, logging_client = pop_default_args(args)
    # Split on whitespace and take last argument because clients might send us flags (-O) in front of the command.
    address = ""
    if "curl" in command_string:
        if "-L" in command_string:
            split_command = command_string.split(' ')
            foundLocationMarker = False
            for command in split_command:
                if foundLocationMarker:
                    address = command
                    break
                if command == "-L":
                    foundLocationMarker = True
    else:
        address = command_string.split(' ')[-1]  # Take the last and hope for the best
    downloaded_file = requests.get(address).content
    try:
        with open('/tmp/malware/' + datetime.now().strftime("%d-%m-%Y-%H-%M-%S-%f") + "@" + command_string.split('/')[-1] + "@" + client_info.ip, 'wb') as saved_file:
            file_sha1 = hashlib.sha1(downloaded_file)
            file_md5 = hashlib.md5(downloaded_file)
            file_sha256 = hashlib.sha256(downloaded_file)
            logging_client.report_event("file", HoneyPotFileEventContent(client_info.ip, "SSH", command_string.split('/')[-1], file_md5.hexdigest(), file_sha1.hexdigest(), file_sha256.hexdigest(), len(downloaded_file)))
            saved_file.write(downloaded_file)
    except Exception as e:
        import traceback
        traceback.print_exc()
    return "\r\n"


def pop_default_args(args):
    return args[0], args[1], args[2]
