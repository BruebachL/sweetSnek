import sys
import inspect
import logging
import os
import socket
import sys
import traceback
from datetime import datetime

import gevent
from netfilterqueue import NetfilterQueue
from scapy.config import conf  # @UnresolvedImport
from scapy.layers.inet import IP, TCP, ICMP, UDP  # @UnresolvedImport
from scapy.supersocket import L3RawSocket  # @UnresolvedImport
from scapy.utils import PcapNgWriter, PcapWriter

from honey_log.client.logging_client import LoggingClient
from honey_log.honeypot_event import HoneyPotUnservicedTCPUDPEventContent, HoneyPotICMPEventContent
from honey_os import session
from honey_os.fingerprint_parser import parse_os_pattern
from honey_os.stack_packet.ICMP_ import check_ICMP_probes
from honey_os.stack_packet.TCP_ import check_TCP_probes
from honey_os.stack_packet.UDP_ import check_UDP_probe
from honey_os.stack_packet.helper import flush_tables
from honey_os.stack_packet.helper import forward_packet
from honey_os.stack_packet.helper import rules
from honey_os.template.os_templates import template_list

if os.path.exists('os_obfuscation.log'):
    os.remove('os_obfuscation.log')
logging.basicConfig(format="[%(asctime)s] %(message)-275s (%(module)s:%(funcName)s:%(lineno)d)",
                    handlers=[logging.FileHandler("os_obfuscation.log")],
                    datefmt='%Y-%m-%d %H:%M:%S', force=True, encoding='utf-8', level=logging.DEBUG)
log = logging.getLogger(__name__)
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# Set Scapy settings
conf.verbose = 0
# using a PF INET/SOCK RAW
conf.L3socket = L3RawSocket
nmap_submodule = LoggingClient("Nmap")


class ProcessPacket(object):
    """
    Do a separation according to the TCP/IP transport layer
    check if the packet is a nmap probe and send OS specific replies
    """

    def __init__(self, os_pattern, session, debug):
        self.os_pattern = os_pattern
        self.session = session
        self.debug = debug
        path = os.path.join("/tmp/malware/", "pcaps")
        if not os.path.exists(path):
            os.mkdir(path, mode=0o666)
        self.pcap_writer = PcapWriter(path + '/' + datetime.now().strftime("%d-%m-%Y-%H-%M-%S-%f") + '_packets.pcap', append=True)

    def callback(self, nfq_packet):
        # Get packet data from nfqueue packet and build a Scapy packet
        packet = IP(nfq_packet.get_payload())
        self.pcap_writer.write(packet)
        # check TCP packets
        if packet.haslayer(TCP):
            if packet.src.split(".")[1] != "127":
                if packet[TCP].flags.S:
                    nmap_submodule.report_event("unservicedtcp",
                                                HoneyPotUnservicedTCPUDPEventContent(packet.src, packet.sport, packet.dport,
                                                                                     True))
                check_TCP_probes(packet, nfq_packet, nmap_submodule, self.os_pattern, self.session, self.debug)


        # check ICMP packets
        elif packet.haslayer(ICMP):
            if packet.src.split(".")[1] != "127":
                nmap_submodule.report_event("unservicedicmp",
                                            HoneyPotICMPEventContent(packet.src, packet.type, packet.code))
                check_ICMP_probes(packet, nfq_packet, nmap_submodule, self.os_pattern)

        # check UDP packets
        elif packet.haslayer(UDP):
            if packet.src.split(".")[1] != "127":
                nmap_submodule.report_event("unservicedudp",
                                            HoneyPotUnservicedTCPUDPEventContent(packet.src, packet.sport, packet.dport,
                                                                                True))
                check_UDP_probe(packet, nfq_packet, nmap_submodule, self.os_pattern)

        # don't analyse it, continue to destination
        else:
            forward_packet(nfq_packet)
        return 0


class ProcessPacketUDP(object):
    """
    Do a separation according to the TCP/IP transport layer
    check if the packet is a nmap probe and send OS specific replies
    """

    def __init__(self, os_pattern, session, debug):
        self.os_pattern = os_pattern
        self.session = session
        self.debug = debug

    def callback(self, nfq_packet):
        # Get packet data from nfqueue packet and build a Scapy packet
        packet = IP(nfq_packet.get_payload())

        forward_packet(nfq_packet)
        return 0


class OSObfuscation(object):

    @classmethod
    def worker(cls, queue):
        while True:
            queue.process_pending(5)

    @classmethod
    def run(cls, debug=False, template_path='', server_ip=None):

        # check if root
        if not os.geteuid() == 0:
            exit("\nPlease run as root\n")
        with open(template_path, "r") as fh:
            data = fh.readlines()
        os_pattern = parse_os_pattern(data)

        if debug:
            print('*' * 30)
            print(os_pattern)
            print('*' * 30)

        log.debug(os_pattern.to_string())

        # Flush the IP tables first
        flush_tables()

        # set iptables rules
        rules(server_ip)
        session_ = session.get_session()
        # creation of a new queue object
        nfqueue = NetfilterQueue()
        nfqueue.bind(0, ProcessPacket(os_pattern, session_, debug).callback)
        s = socket.fromfd(nfqueue.get_fd(), socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            # process queue for packet manipulation
            nfqueue.run_socket(s)
            workers = list()
            for i in range(2):
                workers.append(gevent.spawn(cls.worker, s))
            gevent.joinall(workers)
        except:
            # Exit gracefully to prevent sanity loss and avoid locking iptables
            traceback.print_exc()
            s.close()
            nfqueue.unbind()
            flush_tables()
            print('Exiting...')


if __name__ == '__main__':
    sys.path.append('opt/pycharm-eap/plugins/python/helpers/pydev')
    OSObfuscation.run(
        template_path="/".join(inspect.getabsfile(inspect.currentframe()).split("/")[:-1]) + "/template/os_templates/" +
                      template_list.template_list[template_list.use_template], server_ip="127.0.0.1")
