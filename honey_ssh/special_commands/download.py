import hashlib
from datetime import datetime
import requests

from honey_log.honeypot_event import HoneyPotFileEventContent
from honey_ssh.command_handler import split_command


def pop_default_args(args):
    return args[0], args[1], args[2]


def special_command(args):
    command_string, client_info, logging_client = pop_default_args(args)
    # Split on whitespace and take last argument because clients might send us flags (-O) in front of the command.
    address = ""
    foundLocationMarker = False
    commands = command_string.split(' ')
    for command in commands:
        if "http://" in command or "https://" in command:
            address = command
            foundLocationMarker = True
            break
    if not foundLocationMarker:
        if "-L" in command_string:
            split_command = command_string.split(' ')

            for command in split_command:
                if foundLocationMarker:
                    address = command
                    break
                if "-L" in command:
                    foundLocationMarker = True
        else:
            address = command_string.split(' ')[-1]  # Take the last and hope for the best
            if "http://" not in address:
                address = "http://" + address
    downloaded_file = requests.get(address).content
    try:
        filename = '/tmp/malware/' + datetime.now().strftime("%d-%m-%Y-%H-%M-%S-%f") + "@" + address.split('/')[-1] + "@" + client_info.ip
        with open(filename, 'wb') as saved_file:
            file_sha1 = hashlib.sha1(downloaded_file)
            file_md5 = hashlib.md5(downloaded_file)
            file_sha256 = hashlib.sha256(downloaded_file)
            logging_client.report_event("file", HoneyPotFileEventContent(client_info.ip, "SSH", address.split('/')[-1], file_md5.hexdigest(), file_sha1.hexdigest(), file_sha256.hexdigest(), len(downloaded_file)))
            saved_file.write(downloaded_file)
        if ".sh" in address.split('/')[-1] or "sh" == address.split('/')[-1][len(address.split('/')[-1])-2:]:
            download_files_from_dropper(filename, client_info, logging_client)
    except Exception as e:
        import traceback
        traceback.print_exc()
    return "\r\n"


def download_files_from_dropper(filename, client_info, logging_client):
    with open(filename, 'r') as dropper:
        lines = dropper.readlines()
        for line in lines:
            split_commands = split_command(line)
            for command in split_commands:
                if "wget" in command or "curl" in command:
                    special_command((command.replace("wget ", '').replace('curl ', ''), client_info, logging_client))
