from honey_log.honeypot_event import HoneyPotCMDEventContent
from honey_ssh.special_command_handler import SpecialCommandHandler


def split_command(command_to_split):
    # TODO: Split on & and && and || in correct order.
    split_commands = []
    split_on_semicolon = command_to_split.split(';')
    for semicolon_command in split_on_semicolon:
        split_commands.append(semicolon_command)
    for pipe_command in split_commands:
        split_on_pipes = pipe_command.split('|')
        for command_split_on_pipes in split_on_pipes:
            split_commands.append(command_split_on_pipes)
    return split_commands


class CommandHandler:

    def __init__(self, logging_client, ssh_server, channel, commands):
        self.logging_client = logging_client
        self.ssh_server = ssh_server
        self.client_info = ssh_server.client_info
        self.channel = channel
        self.commands = commands
        self.split_commands = split_command(commands)
        self.known_command_strings = {}
        self.known_commands = {}
        self.known_special_commands = {}
        self.special_command_handler = SpecialCommandHandler()
        self.populate_known_commands()
        self.output_buffer = []

    def populate_known_commands(self):
        from os import listdir
        from os.path import isfile, join
        onlyfiles = [join("./commands/", f) for f in listdir("./commands") if isfile(join("./commands/", f))]
        for filename in onlyfiles:
            try:
                with open(filename) as file:
                    lines = [line.strip('\n').replace('\\n', '\n').replace('\\r', '\r') for line in file.readlines()]
                    if lines[1] == "command_string":
                        self.known_command_strings[lines[0].strip('\n')] = '\r\n'.join(lines[2:]) + '\r\n'
                    elif lines[1] == "command":
                        self.known_commands[lines[0].strip('\n')] = '\r\n'.join(lines[2:]) + '\r\n'
                    elif lines[1] == "special_command":
                        self.known_special_commands[lines[0].strip('\n')] = lines[2]
                    else:
                        # raise Exception('Unknown fake shell command: %' + lines[0])
                        pass
            except Exception as e:
                import traceback
                traceback.print_exc(e)

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
            if not len(self.split_commands) == 1:
                self.logging_client.report_event("cmd", HoneyPotCMDEventContent(self.client_info.ip, "SSH: {}".format(received_command)))
        writemessage.channel.send_exit_status(0)
        self.channel.close()
        return True

    def handle_known_command(self, writemessage, received_command):
        if received_command in self.known_commands:
            writemessage.write(self.known_commands[received_command])
            return True
        else:
            for special_command in self.known_special_commands:
                if special_command in received_command:
                    print("[+] Recognized special command: [%s] in [%s]" % (special_command, received_command))
                    if self.known_special_commands[special_command] in self.special_command_handler.known_special_commands:
                        print("[+] Special command handler knows how to handle this command.")
                        try:
                            print("[+] Letting special command handler handle it.")
                            writemessage.write(self.special_command_handler.known_special_commands[self.known_special_commands[special_command]].special_command((received_command.replace(special_command + " ", ''), self.client_info, self.logging_client)))
                            return True
                        except Exception as e:
                            import traceback
                            traceback.print_exc()
        return False

    def handle_unknown_command(self, writemessage, received_command):
        writemessage.write(
            "'" + received_command + "' is not recognized as an internal or external command, operable program or batch file.\r\n")
        return True
