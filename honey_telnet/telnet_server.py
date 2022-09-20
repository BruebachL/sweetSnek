import argparse
import sys

import gevent
import gevent.server
from telnetsrv.green import TelnetHandler
from telnetsrv.telnetsrvlib import command

from honey_log.client.logging_client2 import LoggingClient2
from honey_log.honeypot_event import HoneyPotLoginEventContent

logging_client = LoggingClient2("Telnet")


class HoneypotTelnetHandler(TelnetHandler):
    WELCOME = "Welcome to Microsoft Telnet Service"
    authNeedUser = True
    authNeedPass = True

    def __init__(self, request, client_address, server):
        self.client_ip = client_address[0].split(':')[-1]
        TelnetHandler.__init__(self, request, client_address, server)

    def authCallback(self, username, password):
        '''Called to validate the username/password.'''
        # Note that this method will be ignored if the SSH server is invoked.
        # We accept everyone here, as long as any name is given!
        logging_client.report_event("login", HoneyPotLoginEventContent(self.client_ip, "Telnet", username, password))
        if not username:
            # complain by raising any exception
            raise

    @command(['echo', 'copy', 'repeat'])
    def command_echo(self, params):
        '''<text to echo>
        Echo text back to the console.

        '''
        self.writeresponse(' '.join(params))

    @command('timer')
    def command_timer(self, params):
        '''<time> <message>
        In <time> seconds, display <message>.
        Send a message after a delay.
        <time> is in seconds.
        If <message> is more than one word, quotes are required.
        example:
        > TIMER 5 "hello world!"
        '''
        try:
            timestr, message = params[:2]
            time = int(timestr)
        except ValueError:
            self.writeerror("Need both a time and a message")
            return
        self.writeresponse("Waiting %d seconds...", time)
        gevent.spawn_later(time, self.writemessage, message)


def start_server(port, bind, interaction_mode):
    server = gevent.server.StreamServer((bind, port), HoneypotTelnetHandler.streamserver_handle)
    server.serve_forever()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Run a Telnet honeypot server')
    parser.add_argument("--port", "-p", help="The port to bind the telnet server to (default 23)", default=23, type=int,
                        action="store")
    parser.add_argument("--bind", "-b", help="The address to bind the telnet server to", default="", type=str,
                        action="store")
    parser.add_argument("--high-interaction", "-hi",
                        help="High interactive (Accept all auths) mode",
                        action="store_true")
    parser.add_argument("--low-interaction", "-li", help="Low interactive (Reject all auths) mode", action="store_true")
    args = parser.parse_args()
    low_interaction_mode = True
    if args.high_interaction and args.low_interaction:
        print(
            "Can't start Telnet Server in both high and low interactive mode. Please only choose one of --high-interaction or --low-interaction")
        sys.exit(1)
    elif not args.high_interaction and not args.low_interaction:
        print("No mode (high/low) selected, defaulting to (safer) low.")
    elif args.high_interaction and not args.low_interaction:
        low_interaction_mode = False
    start_server(args.port, args.bind, False)
