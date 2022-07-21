import time
import json


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


class HoneyPotOtherEventContent:
    def __init__(self, src_ip, tbd):
        self.src_ip = src_ip
        self.tbd = tbd


class HoneypotEventEncoder(json.JSONEncoder):
    def default(self, e):
        if isinstance(e, HoneypotEvent):
            return {"event": e.honeypot_event_details}
        elif isinstance(e, HoneypotEventDetails):
            return {"honeypotID": e.honeypot_id, "token": e.token, "timestamp": e.timestamp, "type": e.type,
                    "content": json.dumps(e.content, cls=HoneypotEventEncoder, indent=0)}
        elif isinstance(e, HoneyPotTCPUDPEventContent):
            return {"srcIP": e.src_ip, "srcPort": e.src_port, "dstPort": e.dst_port}
        elif isinstance(e, HoneyPotICMPEventContent):
            return {"srcIP": e.src_ip, "type": e.icmp_type, "code": e.icmp_code}
        elif isinstance(e, HoneyPotLoginEventContent):
            return {"srcIP": e.src_ip, "service": e.service, "user": e.user, "pass": e.password}
        elif isinstance(e, HoneyPotHTTPEventContent):
            return {"srcIP": e.src_ip, "requestType": e.request_type, "requestString": e.request_string,
                    "agent": e.agent}
        elif isinstance(e, HoneyPotCMDEventContent):
            return {"srcIP": e.src_ip, "cmd": e.cmd}
        elif isinstance(e, HoneyPotNMapScanEventContent):
            return {"srcIP": e.src_ip, "srcOS": e.src_os}
        elif isinstance(e, HoneyPotOtherEventContent):
            return {"srcIP": e.src_ip, "tbd": e.tbd}
        else:
            return super().default(e)

