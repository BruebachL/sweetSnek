import argparse
import inspect
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

        # Import down here so logging server doesn't refuse client connection.
        from osfingerprinting.os_obfuscation import OSObfuscation
        import osfingerprinting.template.os_templates.template_list

        threading.Thread(OSObfuscation.run(
            template_path="/".join(
                inspect.getabsfile(inspect.currentframe()).split("/")[:-1]) + "/osfingerprinting/template/os_templates/" +
                          osfingerprinting.template.os_templates.template_list.template_list[
                              osfingerprinting.template.os_templates.template_list.use_template], server_ip="127.0.0.1")).start()
        sys.exit()
    finally:
        print("Exiting...")
