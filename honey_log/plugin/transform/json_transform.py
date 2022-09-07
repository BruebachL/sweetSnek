import json

from honey_log.honeypot_event import HoneypotEventEncoder


def handle(event, config):
    return fix_up_json_string(json.dumps(event, cls=HoneypotEventEncoder))


def fix_up_json_string(json):
    return json.replace('\\"', '"').replace('\\n', '\n').replace('}\"', '}').replace('\"{', '{')
