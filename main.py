import argparse
import json
import sys
import threading
import time

from event_logging.client.logging_client import LoggingClient
from event_logging.commands.command_log_to_fhws import CommandLogToFHWS, CommandLogToFHWSEncoder
from event_logging.honeypot_event import HoneypotEvent, HoneypotEventDetails, HoneyPotNMapScanEventContent, \
    HoneypotEventEncoder
from event_logging.server.logging_server import LoggingServer

if __name__ == '__main__':
    try:
        parser = argparse.ArgumentParser(description='Submodule logging client.')
        parser.add_argument('--ip', help='Server IP')
        parser.add_argument('--port', help='Server port')
        args = parser.parse_args()
        if args.ip is not None:
            host = args.ip
        else:
            host = None
        if args.port is not None:
            port = args.port
        else:
            port = None

        # Start server and wait a bit to start clients.
        logging_server = LoggingServer(host, port)
        threading.Thread(target=logging_server.listen, args=()).start()
        time.sleep(2)

        nmap_submodule = LoggingClient("Nmap", host, port)
        event = json.dumps(
            HoneypotEvent(HoneypotEventDetails("scan", HoneyPotNMapScanEventContent("127.0.0.1", "Test2"))),
            cls=HoneypotEventEncoder, indent=0).replace('\\"', '"').replace('\\n', '\n').replace('}\"',
                                                                                                 '}').replace(
            '\"{', '{')
        event_to_log = json.dumps(CommandLogToFHWS(event), cls=CommandLogToFHWSEncoder, indent=0).replace('\\"',
                                                                                                          '"').replace(
            '\\n', '\n').replace('}\"',
                                 '}').replace(
            '\"{', '{')
        print("event to log ", event_to_log)
        nmap_submodule.output_buffer.append(bytes(event_to_log, "UTF-8"))
        sys.exit()
    finally:
        print("Exiting...")
