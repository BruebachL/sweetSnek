import argparse
import logging
import threading
import socket
import sys
import traceback
import paramiko
from binascii import hexlify
from paramiko.py3compat import u
from honey_log.client.logging_client import LoggingClient
from honey_log.honeypot_event import HoneyPotLoginEventContent, HoneyPotCMDEventContent

logging_client = LoggingClient("SSH")
HOST_KEY = paramiko.RSAKey(filename='server.key')
SSH_BANNER = "SSH-2.0-OpenSSH_8.2p1 Windows7"

UP_KEY = '\x1b[A'.encode()
DOWN_KEY = '\x1b[B'.encode()
RIGHT_KEY = '\x1b[C'.encode()
LEFT_KEY = '\x1b[D'.encode()
BACK_KEY = '\x7f'.encode()

logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO,
    filename='ssh_honeypot.log')


class LowInteractiveSshHoneypot(paramiko.ServerInterface):
    def __init__(self, client_ip):
        self.event = threading.Event()
        self.client_ip = client_ip

    def check_auth_password(self, username, password):
        logging.info('[+] New client credentials ({}): username: {}, password: {}'.format(
            self.client_ip, username, password))
        logging_client.report_event("login", HoneyPotLoginEventContent(self.client_ip, "SSH", username, password))
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return 'password'


def handle_cmd(cmd, chan, ip):
    response = ""
    if cmd.startswith("ls"):
        response = "users.txt"
    elif cmd.startswith("pwd"):
        response = "C:\\Users\\Administrator"

    if response != '':
        logging.info('Response from honeypot ({}): '.format(ip, response))
        response = response + "\r\n"
    chan.send(response)


class HighInteractiveSshHoneypot(paramiko.ServerInterface):
    client_ip = None

    def __init__(self, client_ip):
        self.client_ip = client_ip
        self.event = threading.Event()

    def check_channel_request(self, kind, chanid):
        logging.info('[i] Client called check_channel_request ({}): {}'.format(
            self.client_ip, kind))
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED

    def get_allowed_auths(self, username):
        logging.info('[i] Client called get_allowed_auths ({}) with username {}'.format(
            self.client_ip, username))
        return "publickey,password"

    def check_auth_publickey(self, username, key):
        fingerprint = u(hexlify(key.get_fingerprint()))
        logging.info(
            '[+] Client public key ({}): username: {}, key name: {}, md5 fingerprint: {}, base64: {}, bits: {}'.format(
                self.client_ip, username, key.get_name(), fingerprint, key.get_base64(), key.get_bits()))
        return paramiko.AUTH_PARTIALLY_SUCCESSFUL

    def check_auth_password(self, username, password):
        # Accept all passwords as valid by default
        logging.info('[+] New client credentials ({}): username: {}, password: {}'.format(
            self.client_ip, username, password))
        logging_client.report_event("login", HoneyPotLoginEventContent(self.client_ip, "SSH", username, password))
        return paramiko.AUTH_SUCCESSFUL

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

    def check_channel_exec_request(self, channel, command):
        command_text = str(command.decode("utf-8"))

        logging.info('client sent command via check_channel_exec_request ({}): {}'.format(
            self.client_ip, command_text))
        logging_client.report_event("cmd", HoneyPotCMDEventContent(self.client_ip, "SSH: {}".format(command_text)))
        writemessage = channel.makefile("w")
        if command_text == "cat /proc/cpuinfo | grep name | wc -l":
            writemessage.write("12")
        else:
            split_commands = split_command(command_text)
            for received_command in split_commands:
                if received_command == "uname -a":
                    writemessage.write(
                        "Linux DESKTOP-VMP6T3Q 4.4.0-19041-Microsoft #1237-Microsoft Sat Sep 11 14:32:00 PST 2021 x86_64 x86_64 x86_64 GNU/Linux\r\n")
                else:
                    writemessage.write(
                        "'" + received_command + "' is not recognized as an internal or external command, operable program or batch file.\r\n")
                logging_client.report_event("cmd", HoneyPotCMDEventContent(self.client_ip, "SSH: {}".format(received_command)))
        writemessage.channel.send_exit_status(0)
        channel.close()
        return True


def split_command(command_to_split):
    split_commands = []
    split_on_semicolon = command_to_split.split(';')
    for semicolon_command in split_on_semicolon:
        split_on_pipes = semicolon_command.split('|')
        for pipe_command in split_on_pipes:
            split_commands.append(pipe_command)
    return split_commands


def handle_connection(client, addr, low_interaction):
    client_ip = addr[0]
    logging.info('[+] New connection from: {}'.format(client_ip))

    try:
        transport = paramiko.Transport(client)
        transport.add_server_key(HOST_KEY)
        transport.local_version = SSH_BANNER  # Change banner to appear more convincing
        if low_interaction:
            server = LowInteractiveSshHoneypot(client_ip)
        else:
            server = HighInteractiveSshHoneypot(client_ip)
        try:
            transport.start_server(server=server)

        except paramiko.SSHException:
            print('[!] SSH negotiation failed.')
            raise Exception("SSH negotiation failed")

        # wait for auth
        chan = transport.accept(10)
        if chan is None:
            print('[!] No channel (from ' + client_ip + ').')
            raise Exception("No channel")

        chan.settimeout(10)

        if transport.remote_mac != '':
            logging.info('[i] Client mac ({}): {}'.format(client_ip, transport.remote_mac))

        if transport.remote_compression != '':
            logging.info('[i] Client compression ({}): {}'.format(client_ip, transport.remote_compression))

        if transport.remote_version != '':
            logging.info('[i] Client SSH version ({}): {}'.format(client_ip, transport.remote_version))

        if transport.remote_cipher != '':
            logging.info('[i] Client SSH cipher ({}): {}'.format(client_ip, transport.remote_cipher))

        if low_interaction and chan is not None:
            chan.close()
            raise Exception("[!] Low interactive honeypot got a channel. Aborting.")

        server.event.wait(10)
        if not server.event.is_set():
            logging.info('[!] Client ({}): never asked for a shell'.format(client_ip))
            raise Exception("No shell request")

        try:
            chan.send(
                "Microsoft Windows [Version 7.0.1049]\r\n(c) 2016 Microsoft Corporation. All rights reserved.\r\n\r\n")
            run = True
            while run:
                chan.send("C:\\Users\\Administrator> ")
                command = ""
                while not command.endswith("\r"):
                    transport = chan.recv(1024)
                    print(client_ip + "- received:", transport)
                    # Echo input to psuedo-simulate a basic terminal
                    if (
                            transport != UP_KEY
                            and transport != DOWN_KEY
                            and transport != LEFT_KEY
                            and transport != RIGHT_KEY
                            and transport != BACK_KEY
                    ):
                        chan.send(transport)
                        command += transport.decode("utf-8")

                chan.send("\r\n")
                command = command.rstrip()
                logging.info('[+] Command received ({}): {}'.format(client_ip, command))

                logging_client.report_event("cmd", HoneyPotCMDEventContent(client_ip, "SSH: {}".format(command)))
                if command == "exit":
                    print("Connection closed (via exit command): " + client_ip + "\n")
                    run = False

                else:
                    handle_cmd(command, chan, client_ip)

        except Exception as err:
            print('[!] Exception: {}: {}'.format(err.__class__, err))
            try:
                transport.close()
            except Exception:
                pass

        chan.close()

    except Exception as err:
        print('[!] Exception: {}: {}'.format(err.__class__, err))
        try:
            transport.close()
        except Exception:
            pass


def start_server(port, bind, low_interaction):
    """Init and run the ssh server"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((bind, port))
    except Exception as err:
        print('[!] Bind failed: {}'.format(err))
        traceback.print_exc()
        sys.exit(1)

    threads = []
    while True:
        try:
            sock.listen(100)
            print('[+] Listening for connection ...')
            client, addr = sock.accept()
        except Exception as err:
            print('[!] Listen/accept failed: {}'.format(err))
            traceback.print_exc()
        new_thread = threading.Thread(target=handle_connection, args=(client, addr, low_interaction))
        new_thread.start()
        threads.append(new_thread)

    for thread in threads:
        thread.join()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Run an SSH honeypot server')
    parser.add_argument("--port", "-p", help="The port to bind the ssh server to (default 22)", default=2222, type=int,
                        action="store")
    parser.add_argument("--bind", "-b", help="The address to bind the ssh server to", default="", type=str,
                        action="store")
    parser.add_argument("--high-interaction", "-hi",
                        help="High interactive (Accept all auths, give them a fake 'shell') mode", action="store_true")
    parser.add_argument("--low-interaction", "-li", help="Low interactive (Reject all auths) mode", action="store_true")
    args = parser.parse_args()
    low_interaction_mode = True
    if args.high_interaction and args.low_interaction:
        print(
            "Can't start SSH Server in both high and low interactive mode. Please only choose one of --high-interaction or --low-interaction")
        sys.exit(1)
    elif not args.high_interaction and not args.low_interaction:
        print("No mode (high/low) selected, defaulting to (safer) low.")
    elif args.high_interaction and not args.low_interaction:
        low_interaction_mode = False
    print(low_interaction_mode)
    start_server(args.port, args.bind, False)
