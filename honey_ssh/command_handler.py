from honey_log.honeypot_event import HoneyPotCMDEventContent


def split_command(command_to_split):
    split_commands = []
    split_on_semicolon = command_to_split.split('; ')
    for semicolon_command in split_on_semicolon:
        split_on_pipes = semicolon_command.split(' | ')
        for pipe_command in split_on_pipes:
            split_commands.append(pipe_command)
    return split_commands


class CommandHandler:

    def __init__(self, logging_client, client_ip, channel, commands):
        self.logging_client = logging_client
        self.client_ip = client_ip
        self.channel = channel
        self.commands = commands
        self.split_commands = split_command(commands)
        self.known_command_strings = {}
        self.known_commands = {}
        self.populate_known_command_string()
        self.output_buffer = []

    def populate_known_command_string(self):
        self.known_command_strings["cat /proc/cpuinfo | grep name | wc -l"] = "12\r\n"
        self.known_command_strings["cat /proc/cpuinfo | grep name | head -n 1 | awk '{print ,,,,,;}'"] = "AMD Ryzen 5 1600X Six-Core Processor\r\n"
        self.known_command_strings["cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'"] = "AMD Ryzen 5 1600X Six-Core Processor\r\n"
        self.known_command_strings["free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'"] = "7957 6355 1420 8 181 1373"
        self.known_command_strings["free -m | grep Mem | awk '{print  ,, , , , }'"] = "7957 6355 1420 8 181 1373"



    def handle_commands(self):
        writemessage = self.channel.makefile("w")
        if self.handle_known_command_string(writemessage):
            return True
        else:
            return self.handle_unknown_command_string(writemessage)

    def handle_known_command_string(self, writemessage):
        if self.commands in self.known_command_strings:
            writemessage.write(self.known_command_strings[self.commands])
        else:
            return False
        writemessage.channel.send_exit_status(0)
        self.channel.close()
        return True

    def handle_unknown_command_string(self, writemessage):
        for received_command in self.split_commands:
            if not self.handle_known_command(writemessage, received_command):
                self.handle_unknown_command(writemessage, received_command)
            self.logging_client.report_event("cmd", HoneyPotCMDEventContent(self.client_ip, "SSH: {}".format(received_command)))
        writemessage.channel.send_exit_status(0)
        self.channel.close()
        return True

    def handle_known_command(self, writemessage, received_command):
        if received_command == "uname -a":
            writemessage.write(
                "Linux DESKTOP-VMP6T3Q 4.4.0-19041-Microsoft #1237-Microsoft Sat Sep 11 14:32:00 PST 2021 x86_64 x86_64 x86_64 GNU/Linux\r\n")
        else:
            return False
        return True

    def handle_unknown_command(self, writemessage, received_command):
        writemessage.write(
            "'" + received_command + "' is not recognized as an internal or external command, operable program or batch file.\r\n")
        return True
