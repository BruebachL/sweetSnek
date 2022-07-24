class LoggingClientRecord:

    def __init__(self, socket, address, friendly_name):
        self.socket = socket
        self.address = address
        self.name = friendly_name

    def set_name(self, friendly_name):
        self.name = friendly_name
