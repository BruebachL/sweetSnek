import argparse
import os
import sys

from pyftpdlib.filesystems import AbstractedFS
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer

from honey_ftp.honeypot_authorizer import HoneyPotAuthorizer, DummyAuthorizer
from honey_log.client.logging_client import LoggingClient

logging_client = LoggingClient("FTP")
path = os.path.join("/tmp/malware/", "ftp")
if not os.path.exists(path):
    os.mkdir(path, mode=0o666)


def start_server(port, bind, interaction_mode):
    authorizer = HoneyPotAuthorizer(logging_client, interaction_mode)
    anonymous_home = os.path.join("/tmp/malware/ftp/", "anonymous")
    if not os.path.exists(anonymous_home):
        os.mkdir(anonymous_home, mode=0o666)
    authorizer.add_anonymous("/tmp/malware/ftp/anonymous")

    handler = FTPHandler
    handler.authorizer = authorizer
    handler.abstracted_fs = AbstractedFS

    server = FTPServer((bind, port), handler)

    # set a limit for connections to prevent DDoS
    server.max_cons = 512
    server.max_cons_per_ip = 25

    server.serve_forever()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Run an SSH honeypot server')
    parser.add_argument("--port", "-p", help="The port to bind the ftp server to (default 21)", default=21, type=int,
                        action="store")
    parser.add_argument("--bind", "-b", help="The address to bind the ftp server to", default="", type=str,
                        action="store")
    parser.add_argument("--high-interaction", "-hi",
                        help="High interactive (Accept all auths, give them a fake chroot filesystem) mode",
                        action="store_true")
    parser.add_argument("--low-interaction", "-li", help="Low interactive (Reject all auths) mode", action="store_true")
    args = parser.parse_args()
    low_interaction_mode = True
    if args.high_interaction and args.low_interaction:
        print(
            "Can't start FTP Server in both high and low interactive mode. Please only choose one of --high-interaction or --low-interaction")
        sys.exit(1)
    elif not args.high_interaction and not args.low_interaction:
        print("No mode (high/low) selected, defaulting to (safer) low.")
    elif args.high_interaction and not args.low_interaction:
        low_interaction_mode = False
    print(low_interaction_mode)
    start_server(args.port, args.bind, False)
