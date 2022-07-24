import json
import logging
import os
import socket
import threading
import traceback

from event_logging.commands.command_log_to_fhws import CommandLogToFHWS
from event_logging.event_logger import EventLogger
from event_logging.honeypot_event import decode_honeypot_event, HoneypotEventEncoder
from event_logging.server.logging_client_record import LoggingClientRecord


class LoggingServer(object):
    def __init__(self, host=None, port=None):
        if host is None:
            host = socket.gethostname()
        if port is None:
            port = 6000
        self.host = host
        self.port = port
        print("Starting logging server on {}:{} ...".format(self.host, self.port))
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.host, self.port))
        print("Logging server started and listening on {}:{}!".format(self.host, self.port))
        self.connected_clients = []
        self.log = self.setup_logger("logging_server.log")  # Internal logging, not related to honeypot events.
        self.event_logger = EventLogger(self.log)

    def setup_logger(self, log_name):
        if os.path.exists(log_name):
            os.remove(log_name)
        server_log = logging.Logger(log_name)
        server_handler = logging.FileHandler(log_name)
        server_formatter = logging.Formatter(fmt="[%(asctime)s] %(message)-160s (%(module)s:%(funcName)s:%(lineno)d)", datefmt='%Y-%m-%d %H:%M:%S')
        server_handler.setFormatter(server_formatter)
        server_log.addHandler(server_handler)
        return server_log

    def decode_command(self, command):
        formatted_cmd = str(command).replace('\'', '\"')
        self.log.debug(formatted_cmd)
        match command['class']:
            case "command_log_to_fhws":
                return CommandLogToFHWS(json.loads(command['event_to_log'], object_hook=decode_honeypot_event))

    def execute_command(self, client, command):
        cmd = json.loads(command, object_hook=decode_honeypot_event)
        self.log.debug(type(cmd))
        self.event_logger.async_report_event(json.dumps(cmd, cls=HoneypotEventEncoder))

    def listen(self):
        self.sock.listen(5)
        while True:
            client, address = self.sock.accept()
            client.settimeout(60)
            client_record = LoggingClientRecord(client, address, "")
            self.connected_clients.append(client_record)
            self.log.debug("Client connected...")
            threading.Thread(target=self.listen_to_client, args=(client_record,)).start()

    def send_to_clients(self, response):
        for connected_client in self.connected_clients:
            self.announce_length_and_send(connected_client, response)

    def announce_length_and_send(self, client, output):
        self.log.debug("Announcing length of " + str(len(output)) + " to Client (" + client.getpeername()[0] + ":" + str(
            client.getpeername()[1]) + ")")
        client.sendall(len(output).to_bytes(12, 'big'))
        self.log.debug("Sending to Client (" + client.getpeername()[0] + ":" + str(client.getpeername()[1]) + ")")
        client.sendall(output)
        self.log.debug("Sent " + str(output, "UTF-8") + " with length " + str(len(output)) + " to " + str(client.getpeername()))

    def listen_until_all_data_received(self, client):
        self.log.debug("Listening to Client (" + client.getpeername()[0] + ":" + str(client.getpeername()[1]) + ") ...")
        length = int.from_bytes(client.recv(12), 'big')
        self.log.debug("Client (" + client.getpeername()[0] + ":" + str(client.getpeername()[1]) + ") announced " + str(
            length) + " of data.")
        data = ""
        left_to_receive = length
        while len(data) != length:
            received = str(client.recv(left_to_receive), "UTF-8")
            data = data + received
            left_to_receive = left_to_receive - (len(received))
            self.log.debug("Received " + str(len(received)) + " from Client (" + client.getpeername()[0] + ":" + str(
                client.getpeername()[1]) + ") and have " + str(left_to_receive) + " left to receive.")
        self.log.debug("Received " + data + " with length " + str(length))
        return data

    def listen_to_client(self, client_record):
        # First thing we receive from the client is its friendly name :)
        friendly_name = self.listen_until_all_data_received(client_record.socket)
        client_record.set_name(friendly_name)
        print("{} connected!".format(friendly_name))
        while True:
            try:
                data = self.listen_until_all_data_received(client_record.socket)
                self.log.debug(data)
                if data:
                    # Set the response to echo back the received data
                    response = self.execute_command(client_record.socket, data)
                    # self.send_to_clients(bytes(str(response), "UTF-8"))
                else:
                    raise ConnectionError('Client disconnected')
            except TimeoutError as t:
                print("Removing client {} (Reason: Timed out) ...".format(client_record.name))
                self.connected_clients.remove(client_record)
                client_record.socket.close()
                print("Client closed.")
                return False
            except ConnectionError as c:
                print("Removing client {} (Reason: Client disconnected.) ...".format(client_record.name))
                self.connected_clients.remove(client_record)
                client_record.socket.close()
                print("Client closed.")
                return False
            except Exception as e:
                traceback.print_exc()


if __name__ == '__main__':
    LoggingServer(socket.gethostname(), 6000).listen()
    # listener = Listener(('localhost', 6000), authkey=b'secret password')
    # running = True
    # while running:
    #     conn = listener.accept()
    #     print('connection accepted from', listener.last_accepted)
    #     while True:
    #         msg = conn.recv()
    #         print(msg)
    #         if msg == 'close connection':
    #             event = json.dumps(
    #                 HoneypotEvent(HoneypotEventDetails("scan", HoneyPotNMapScanEventContent("127.0.0.1", "Test"))),
    #                 cls=HoneypotEventEncoder, indent=0).replace('\\"', '"').replace('\\n', '\n').replace('}\"',
    #                                                                                                      '}').replace(
    #                 '\"{', '{')
    #             event_logger.async_report_event(event)
    #             conn.close()
    #             break
    #         if msg == 'close server':
    #             conn.close()
    #             running = False
    #             break
    # listener.close()
