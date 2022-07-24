import json


class CommandLogToFHWS:
    """
        Holds options for the wps attacks
    """

    def __init__(self, event_to_log):
        self.event_to_log = event_to_log


def decode_command_log_to_fhws(dct):
    if 'class' in dct:
        if dct['class'] == "command_log_to_fhws":
            print(dct)
            print("decode debug ",dct['event_to_log'])
            return CommandLogToFHWS(dct['event_to_log'])
    return dct


class CommandLogToFHWSEncoder(json.JSONEncoder):
    def default(self, c):
        if isinstance(c, CommandLogToFHWS):
            return {"class": 'command_log_to_fhws', "event_to_log": c.event_to_log}
        else:
            return super().default(c)
