import argparse
import json
import logging
import os
import select
import socket
import sys
import threading
import time
#from pathlib import Path

from honey_log.honeypot_event import HoneypotEvent, HoneyPotNMapScanEventContent, HoneypotEventEncoder, \
    HoneypotEventDetails, fix_up_json_string
from honey_log.commands.command_log_to_fhws import CommandLogToFHWS, CommandLogToFHWSEncoder


class LoggingClient:
    def __init__(self, submodule_name, logging_host=None, port=None):
        if logging_host is None:
            logging_host = socket.gethostname()
        if port is None:
            port = 6000

        #self.base_path = Path(os.path.dirname(Path(sys.path[0])))
        self.submodule_name = submodule_name
        # Network things
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if logging_host is None:
            logging_host = socket.gethostname()
        if port is None:
            port = 6000
        self.log = self.setup_logger(self.submodule_name + "_logging_client.log")  # Internal logging, not related to honeypot events.
        self.logging_host = logging_host
        self.port = port
        sock.connect((logging_host, port))
        sock.setblocking(False)
        self.connected_socket = sock
        self.announce_length_and_send(sock, bytes(submodule_name, 'UTF-8'))
        self.output_buffer = []

        # Connect timer to check for updates and send to server
        threading.Timer(1, self.check_for_updates_and_send_output_buffer).start()

    def setup_logger(self, log_name):
        if os.path.exists(log_name):
            os.remove(log_name)
        client_log = logging.Logger(log_name)
        client_handler = logging.FileHandler(log_name)
        client_formatter = logging.Formatter(fmt="[%(asctime)s] %(message)-160s (%(module)s:%(funcName)s:%(lineno)d)",
                                             datefmt='%Y-%m-%d %H:%M:%S')
        client_handler.setFormatter(client_formatter)
        client_log.addHandler(client_handler)
        return client_log

    def attempt_reconnect_to_server(self):
        not_connected = True
        while not_connected:
            try:
                self.log.debug("Attempting to connect to {}:{}".format(self.logging_host, self.port))
                self.connected_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.connected_socket.connect((self.logging_host, self.port))
                self.log.debug("Connected to {}:{}".format(self.logging_host, self.port))
                self.announce_length_and_send(self.connected_socket, bytes(self.submodule_name, 'UTF-8'))
                not_connected = False
            except socket.error:
                self.log.debug("Failed reconnection attempt to {}:{}".format(self.logging_host, self.port))
                time.sleep(1)

    def listen_until_all_data_received(self, server):
        self.log.debug(
            "Client listening to server (" + server.getpeername()[0] + ":" + str(server.getpeername()[1]) + ") ...")
        length = int.from_bytes(server.recv(12), 'big')
        self.log.debug(
            "Server (" + server.getpeername()[0] + ":" + str(server.getpeername()[1]) + ") announced " + str(
                length) + " of data.")
        data = ""
        left_to_receive = length
        while len(data) != length:
            server.setblocking(True)
            partial_data = server.recv(left_to_receive)
            self.log.debug(partial_data)
            received = str(partial_data, "UTF-8")
            data = data + received
            left_to_receive = left_to_receive - (len(received))
        server.setblocking(False)
        return data

    def decode_server_command(self, command):
        if isinstance(command, str):
            command = json.loads(command)
        self.log.debug(command)
        # match command['class']:
        #     case "command_roll_dice":
        #         print("Client decoded command roll dice.")
        #         return json.loads(str(command).replace('\'', '\"').replace('True', 'true').replace('False', 'false'),
        #                           object_hook=decode_command_roll_dice)

    def process_server_response(self, response):
        self.log.debug("Server sent something.")
        # match response:
        #     case CommandListenUp():
        #         listen_up = json.loads(str(response), object_hook=decode_listen_up)
        #         self.receive_file_from_server(listen_up.length, listen_up.port, listen_up.file_name)

    def announce_length_and_send(self, server, output):
        server.sendall(len(output).to_bytes(12, 'big'))
        self.log.debug(
            "Announced " + str(len(output)) + " to Server (" + server.getpeername()[0] + ":" + str(
                server.getpeername()[1]) + ")")
        server.sendall(output)
        self.log.debug(
            "Sent all to Server (" + server.getpeername()[0] + ":" + str(server.getpeername()[1]) + ")")

    def check_for_updates_and_send_output_buffer(self):
        read_sockets, write_sockets, error_sockets = select.select(
            [self.connected_socket], [self.connected_socket], [self.connected_socket])

        for read_sock in read_sockets:
            # incoming message from remote server
            try:
                received_command = self.listen_until_all_data_received(read_sock)
            except OSError as e:
                self.log.debug("Server disconnected. Recovering...")
                self.attempt_reconnect_to_server()
                break

            self.log.debug("Received: " + received_command)
            if not received_command:
                self.log.debug('\nDisconnected from server')
                self.attempt_reconnect_to_server()
                break
            else:
                cmd = json.loads(received_command, object_hook=self.decode_server_command)
                if received_command != "None":
                    self.log.debug(cmd)
                    self.process_server_response(cmd)

        for write_sock in write_sockets:
            if len(self.output_buffer) > 0:
                for output in self.output_buffer:
                    self.log.debug("Sent: " + str(output, "UTF-8"))
                    self.announce_length_and_send(write_sock, output)
                self.output_buffer.clear()
        threading.Timer(1, self.check_for_updates_and_send_output_buffer).start()

    def report_event(self, event_type, event_to_report):
        self.output_buffer.append(bytes(fix_up_json_string(json.dumps(HoneypotEvent(HoneypotEventDetails(event_type, event_to_report)), cls=HoneypotEventEncoder, indent=0)), "UTF-8"))


if __name__ == '__main__':
    try:
        time.sleep(1)
        parser = argparse.ArgumentParser(description='Submodule logging client.')
        parser.add_argument('--ip', help='Server IP')
        parser.add_argument('--name', help='Character name')
        args = parser.parse_args()
        if args.ip is not None:
            host = args.ip
        else:
            host = None
        if args.name is not None:
            player = args.name
        else:
            player = "Dummy"
        window = LoggingClient(player, host, 6000)
        event = json.dumps(
            HoneypotEvent(HoneypotEventDetails("scan", HoneyPotNMapScanEventContent("127.0.0.1", "Test"))),
            cls=HoneypotEventEncoder, indent=0).replace('\\"', '"').replace('\\n', '\n').replace('}\"',
                                                                                                 '}').replace(
            '\"{', '{')
        event_to_log = json.dumps(CommandLogToFHWS(event), cls=CommandLogToFHWSEncoder, indent=0).replace('\\"',
                                                                                                          '"').replace(
            '\\n', '\n').replace('}\"',
                                 '}').replace(
            '\"{', '{')
        print("event to log ", event_to_log)
        window.output_buffer.append(bytes(event_to_log, "UTF-8"))
        sys.exit()
    finally:
        print("Exiting...")
