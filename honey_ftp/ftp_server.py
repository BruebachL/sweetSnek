import argparse
import sys

from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.filesystems import AbstractedFS
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer

from honey_ftp.honeypot_authorizer import HoneyPotAuthorizer
from honey_log.client.logging_client import LoggingClient

logging_client = LoggingClient("FTP")

def start_server(port, bind, interaction_mode):
    authorizer = HoneyPotAuthorizer(logging_client)
    # authorizer.add_user("user", "12345", "/home/giampaolo", perm="elradfmwMT")
    authorizer.add_anonymous("/tmp/malware/ftp")

    handler = FTPHandler
    handler.authorizer = authorizer
    handler.abstracted_fs = AbstractedFS

    server = FTPServer(("127.0.0.1", 21), handler)
    server.serve_forever()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Run an SSH honeypot server')
    parser.add_argument("--port", "-p", help="The port to bind the ftp server to (default 21)", default=2222, type=int,
                        action="store")
    parser.add_argument("--bind", "-b", help="The address to bind the ftp server to", default="", type=str,
                        action="store")
    parser.add_argument("--high-interaction", "-hi",
                        help="High interactive (Accept all auths, give them a fake chroot filesystem) mode", action="store_true")
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