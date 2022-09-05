import logging
import os
import time
import json

log_name = "honeypot_event_json.log"
if os.path.exists(log_name):
    os.remove(log_name)
server_log = logging.Logger(log_name)
server_handler = logging.FileHandler(log_name)
server_formatter = logging.Formatter(fmt="[%(asctime)s] %(message)-160s (%(module)s:%(funcName)s:%(lineno)d)",
                                     datefmt='%Y-%m-%d %H:%M:%S')
server_handler.setFormatter(server_formatter)
server_log.addHandler(server_handler)


class HoneypotEvent:
    def __init__(self, honeypot_event_details):
        self.honeypot_event_details = honeypot_event_details


class HoneypotEventDetails:
    def __init__(self, event_type, content):
        self.honeypot_id = 2
        self.token = "f889466ef38ba332d490d869872fa79e9144763df03dde2a9ba84dc6626663c2"
        self.timestamp = time.time()
        self.type = event_type
        self.content = content


class HoneyPotTCPUDPEventContent:
    def __init__(self, src_ip, src_port, dst_port):
        self.src_ip = src_ip
        self.src_port = src_port
        self.dst_port = dst_port


class HoneyPotICMPEventContent:
    def __init__(self, src_ip, icmp_type, icmp_code):
        self.src_ip = src_ip
        self.icmp_type = icmp_type
        self.icmp_code = icmp_code


class HoneyPotLoginEventContent:
    def __init__(self, src_ip, service, user, password):
        self.src_ip = src_ip
        self.service = service
        self.user = user
        self.password = password


class HoneyPotHTTPEventContent:
    def __init__(self, src_ip, request_type, request_string, agent):
        self.src_ip = src_ip
        self.request_type = request_type
        self.request_string = request_string
        self.agent = agent


class HoneyPotCMDEventContent:
    def __init__(self, src_ip, cmd):
        self.src_ip = src_ip
        self.cmd = cmd


class HoneyPotNMapScanEventContent:
    def __init__(self, src_ip, src_os):
        self.src_ip = src_ip
        self.src_os = src_os


class HoneyPotSMBEventContent:

    def __init__(self, src_ip, data):
        self.src_ip = src_ip
        self.data = data


class HoneyPotFileEventContent:

    def __init__(self, src_ip, service, fname, md5, sha1, sha256, size):
        self.src_ip = src_ip
        self.service = service
        self.fname = fname
        self.md5 = md5
        self.sha1 = sha1
        self.sha256 = sha256
        self.size = size


class HoneyPotOtherEventContent:
    def __init__(self, src_ip, tbd):
        self.src_ip = src_ip
        self.tbd = tbd


def decode_honeypot_event(dct):
    if 'event' in dct:
        server_log.debug("Decoded Honeypot event from:")
        server_log.debug(dct)
        return HoneypotEvent(dct['event'])
    if 'honeypotID' in dct and 'token' in dct and 'timestamp' in dct and 'type' in dct and 'content' in dct:
        event_details = HoneypotEventDetails(dct['type'], dct['content'])
        event_details.timestamp = dct['timestamp']
        server_log.debug("Decoded Honeypot Event Details from: ")
        server_log.debug(dct)
        return event_details
    if 'srcIP' in dct:
        if 'srcPort' in dct and 'dstPort' in dct:
            server_log.debug("Decoded Honeypot TCP/UDP Event Details from: ")
            server_log.debug(dct)
            return HoneyPotTCPUDPEventContent(dct['srcIP'], dct['srcPort'], dct['dstPort'])
        if 'type' in dct and 'code' in dct:
            server_log.debug("Decoded Honeypot ICMP Event Details from: ")
            server_log.debug(dct)
            return HoneyPotICMPEventContent(dct['srcIP'], dct['type'], dct['code'])
        if 'service' in dct and 'user' in dct and 'pass' in dct:
            server_log.debug("Decoded Honeypot Login Event Details from: ")
            server_log.debug(dct)
            return HoneyPotLoginEventContent(dct['srcIP'], dct['service'], dct['user'], dct['pass'])
        if 'requestType' in dct and 'requestString' in dct and 'agent' in dct:
            server_log.debug("Decoded Honeypot HTTP Event Details from: ")
            server_log.debug(dct)
            return HoneyPotHTTPEventContent(dct['srcIP'], dct['requestType'], dct['requestString'], dct['agent'])
        if 'cmd' in dct:
            server_log.debug("Decoded Honeypot Cmd Event Details from: ")
            server_log.debug(dct)
            return HoneyPotCMDEventContent(dct['srcIP'], dct['cmd'])
        if 'srcOS' in dct:
            server_log.debug("Decoded Honeypot Scan Event Details from: ")
            server_log.debug(dct)
            return HoneyPotNMapScanEventContent(dct['srcIP'], dct['srcOS'])
        if 'smb' in dct:
            server_log.debug("Decoded Honeypot SMB Cmd Event Details from: ")
            server_log.debug(dct)
            return HoneyPotSMBEventContent(dct['srcIP'], dct['data'])
        if 'service' in dct and 'fname' in dct and 'md5' in dct and 'sha1' in dct and 'sha256' in dct and 'size' in dct:
            server_log.debug("Decoded Honeypot File Event Details from: ")
            server_log.debug(dct)
            return HoneyPotFileEventContent(dct['srcIP'], dct['service'], dct['fname'], dct['md5'], dct['sha1'], dct['sha256'], dct['size'])
        if 'tbd' in dct:
            server_log.debug("Decoded Honeypot Other Event Details from: ")
            server_log.debug(dct)
            return HoneyPotOtherEventContent(dct['srcIP'], dct['tbd'])
        return dct


def fix_up_json_string(json):
    return json.replace('\\"', '"').replace('\\n', '\n').replace('}\"', '}').replace('\"{', '{')


class HoneypotEventEncoder(json.JSONEncoder):
    def default(self, e):
        server_log.debug("Encoding Honeypot even from: ")
        server_log.debug(e)
        server_log.debug(" to ")
        if isinstance(e, HoneypotEvent):
            server_log.debug({"event": e.honeypot_event_details})
            return {"event": e.honeypot_event_details}
        elif isinstance(e, HoneypotEventDetails):
            server_log.debug({"honeypotID": e.honeypot_id, "token": e.token, "timestamp": e.timestamp, "type": e.type,
                              "content": json.dumps(e.content, cls=HoneypotEventEncoder, indent=0, ensure_ascii=False)})
            return {"honeypotID": e.honeypot_id, "token": e.token, "timestamp": e.timestamp, "type": e.type,
                    "content": json.dumps(e.content, cls=HoneypotEventEncoder, indent=0, ensure_ascii=False)}
        elif isinstance(e, HoneyPotTCPUDPEventContent):
            server_log.debug({"srcIP": e.src_ip, "srcPort": e.src_port, "dstPort": e.dst_port})
            return {"srcIP": e.src_ip, "srcPort": e.src_port, "dstPort": e.dst_port}
        elif isinstance(e, HoneyPotICMPEventContent):
            server_log.debug({"srcIP": e.src_ip, "type": e.icmp_type, "code": e.icmp_code})
            return {"srcIP": e.src_ip, "type": e.icmp_type, "code": e.icmp_code}
        elif isinstance(e, HoneyPotLoginEventContent):
            server_log.debug({"srcIP": e.src_ip, "service": e.service, "user": e.user, "pass": e.password})
            return {"srcIP": e.src_ip, "service": e.service, "user": e.user, "pass": e.password}
        elif isinstance(e, HoneyPotHTTPEventContent):
            server_log.debug({"srcIP": e.src_ip, "requestType": e.request_type, "requestString": e.request_string,
                              "agent": e.agent})
            return {"srcIP": e.src_ip, "requestType": e.request_type, "requestString": e.request_string,
                    "agent": e.agent}
        elif isinstance(e, HoneyPotCMDEventContent):
            server_log.debug({"srcIP": e.src_ip, "cmd": e.cmd})
            return {"srcIP": e.src_ip, "cmd": e.cmd}
        elif isinstance(e, HoneyPotNMapScanEventContent):
            server_log.debug({"srcIP": e.src_ip, "srcOS": e.src_os})
            return {"srcIP": e.src_ip, "srcOS": e.src_os}
        elif isinstance(e, HoneyPotSMBEventContent):
            return {"srcIP": e.src_ip, "data": e.data}
        elif isinstance(e, HoneyPotFileEventContent):
            return {'srcIP': e.src_ip, 'service': e.service, 'fname': e.fname, 'md5': e.md5, 'sha1': e.sha1, 'sha256': e.sha256, 'size': e.size}
        elif isinstance(e, HoneyPotOtherEventContent):
            server_log.debug({"srcIP": e.src_ip, "tbd": e.tbd})
            return {"srcIP": e.src_ip, "tbd": e.tbd}
        else:
            return super().default(e)
