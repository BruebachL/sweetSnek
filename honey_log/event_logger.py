import json
from honey_log.honeypot_event import HoneypotEvent, HoneypotEventDetails, \
    HoneypotEventEncoder, fix_up_json_string, HoneyPotTCPUDPEventContent, \
    HoneyPotICMPEventContent
from honey_log.plugin.plugin_handler import PluginHandler
from honey_os.session import Session


def get_source_and_destination_port_from_event(event):
    if isinstance(event.honeypot_event_details.content, dict):
        return event.honeypot_event_details.content['src_port'], event.honeypot_event_details.content['dst_port']
    else:
        return event.honeypot_event_details.content.src_port, event.honeypot_event_details.content.dst_port


def get_icmp_type_and_code_from_event(event):
    if isinstance(event.honeypot_event_details.content, dict):
        return event.honeypot_event_details.content['icmp_type'], event.honeypot_event_details.content['icmp_code']
    else:
        return event.honeypot_event_details.content.icmp_type, event.honeypot_event_details.content.icmp_code


class EventLogger:
    def __init__(self, logger, no_reporting):
        self.event_id = 0
        self.log = logger
        self.no_reporting = no_reporting
        self.plugin_handler = PluginHandler()
        self.plugin_handler.print_plugins()
        self.session = Session()

    def async_report_event(self, event, srcIP):
        self.log.debug("Checking event...: {}".format(event))
        event = self.check_if_event_needs_reporting(event, srcIP)
        if event is not None:
            json_event = fix_up_json_string(json.dumps(event, cls=HoneypotEventEncoder))
            self.plugin_handler.handle_event(event)
            print("Async reporting event. ", json_event)

    def check_if_event_needs_reporting(self, event, srcIP):
        if event.honeypot_event_details.type == "unservicedtcp" or event.honeypot_event_details.type == "unservicedudp" or event.honeypot_event_details.type == "unservicedicmp":
            if event.honeypot_event_details.type == "unservicedicmp":
                return self.check_if_icmp_event_needs_reporting(srcIP, event)
            else:
                return self.check_if_tcp_udp_event_needs_reporting(srcIP, event)
        else:
            return event

    def check_if_tcp_udp_event_needs_reporting(self, srcIP, event):
        srcPort, dstPort = get_source_and_destination_port_from_event(event)

        if self.session.port_in_session(srcIP, event.honeypot_event_details.type, srcPort, dstPort):
            print("Port in session.")
            return None
        else:
            print("Port not in session, reporting %s event..." % event.honeypot_event_details.type.replace('unserviced',
                                                                                                           ''))
            return HoneypotEvent(HoneypotEventDetails(event.honeypot_event_details.type.replace('unserviced', ''),
                                                      HoneyPotTCPUDPEventContent(srcIP, srcPort, dstPort)))

    def check_if_icmp_event_needs_reporting(self, srcIP, event):
        icmp_type, icmp_code = get_icmp_type_and_code_from_event(event)

        if self.session.in_session(srcIP, False, self.log):
            print("IP in session.")
            return None
        else:
            print("IP not in session, reporting %s event..." % event.honeypot_event_details.type.replace('unserviced',
                                                                                                         ''))
            return HoneypotEvent(HoneypotEventDetails(event.honeypot_event_details.type.replace('unserviced', ''),
                                                      HoneyPotICMPEventContent(srcIP, icmp_type, icmp_code)))
