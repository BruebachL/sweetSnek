import asyncio
import json
import sys
import traceback

import gevent
import logging
import os
import inspect
import socket

from scapy.ansmachine import AnsweringMachine
from scapy.arch import get_if_addr
from scapy.fields import BitEnumField, IPField, ShortField, BitField, FlagsField
from scapy.interfaces import get_if_list
from scapy.layers.netbios import NBNSQueryRequest, NBNSQueryResponse
from scapy.layers.smb import NTLM_SMB_Server
from scapy.packet import Packet, Raw

import event_logger
import session
from honeypot_event import HoneypotEvent, HoneypotEventDetails, HoneyPotTCPUDPEventContent, HoneypotEventEncoder

from osfingerprinting.template.os_templates import template_list
from fingerprint_parser import parse_os_pattern
from netfilterqueue import NetfilterQueue
from scapy.layers.inet import IP, TCP, ICMP, UDP  # @UnresolvedImport
from scapy.config import conf  # @UnresolvedImport
from scapy.supersocket import L3RawSocket, SuperSocket  # @UnresolvedImport

from smb import smb_server
from smb.netbios.name_server.name_service_packet_header import NameServicePacketHeader, NameServicePacketHeaderFlags
from stack_packet.ICMP_ import check_ICMP_probes
from stack_packet.TCP_ import check_TCP_probes
from stack_packet.UDP_ import check_UDP_probe
from stack_packet.helper import flush_tables, get_packet_layers, print_packet
from stack_packet.helper import forward_packet
from stack_packet.helper import rules

if os.path.exists('example.log'):
    os.remove('example.log')
logging.basicConfig(format="[%(asctime)s] %(message)-275s (%(module)s:%(funcName)s:%(lineno)d)",
                    handlers=[logging.FileHandler("example.log"),
                              logging.StreamHandler()],
                    datefmt='%Y-%m-%d %H:%M:%S', force=True, encoding='utf-8', level=logging.DEBUG)
log = logging.getLogger(__name__)
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# Set Scapy settings
conf.verbose = 0
# using a PF INET/SOCK RAW
conf.L3socket = L3RawSocket


class ProcessPacket(object):
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

        # check TCP packets
        if packet.haslayer(TCP):
            check_TCP_probes(packet, nfq_packet, self.os_pattern, self.session, self.debug)

        # check ICMP packets
        elif packet.haslayer(ICMP):
            check_ICMP_probes(packet, nfq_packet, self.os_pattern)

        # check UDP packets
        elif packet.haslayer(UDP):
            check_UDP_probe(packet, nfq_packet, self.os_pattern)

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
        print("UDP lol")

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

        print(os_pattern.to_string())

        # Flush the IP tables first
        flush_tables()

        # set iptables rules
        rules(server_ip)
        session_ = session.get_session()
        # creation of a new queue object
        nfqueue = NetfilterQueue()
        nfqueue.bind(0, ProcessPacket(os_pattern, session_, debug).callback)
        print("Bound first.")
        udp_nfqueue = NetfilterQueue()
        print("Bound second.")
        udp_nfqueue.bind(1, ProcessPacketUDP(os_pattern, session_, debug).callback)
        s = socket.fromfd(nfqueue.get_fd(), socket.AF_UNIX, socket.SOCK_STREAM)
        u = socket.fromfd(udp_nfqueue.get_fd(), socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            # process queue for packet manipulation
            nfqueue.run_socket(s)
            udp_nfqueue.run_socket(u)
            workers = list()
            udp_workers = list()
            for i in range(2):
                workers.append(gevent.spawn(cls.worker, s))
                udp_workers.append(gevent.spawn(cls.worker, u))
            gevent.joinall(udp_workers)
            gevent.joinall(workers)
        except:
            # Exit gracefully to prevent sanity loss and avoid locking iptables
            traceback.print_exc()
            s.close()
            u.close()
            nfqueue.unbind()
            udp_nfqueue.unbind()
            flush_tables()
            print('Exiting...')


if __name__ == '__main__':
    # event_logger = event_logger.EventLogger()
    # loop = asyncio.new_event_loop()
    # event = json.dumps(HoneypotEvent(HoneypotEventDetails("tcp", HoneyPotTCPUDPEventContent("127.0.0.2", "1337", "1338"))), cls=HoneypotEventEncoder, indent=0).replace('\\"', '"').replace('\\n', '\n').replace('}\"', '}').replace('\"{', '{')
    # try:
    #     loop.run_until_complete(event_logger.async_report_event(event))
    # finally:
    #     loop.close()
    smb_server = NTLM_SMB_Server([Raw, "127.0.0.1", 137])
    smb_server.run()

    sys.path.append('opt/pycharm-eap/plugins/python/helpers/pydev')
    OSObfuscation.run(
        template_path="/".join(inspect.getabsfile(inspect.currentframe()).split("/")[0:6]) + "/template/os_templates/" +
                      template_list.template_list[template_list.use_template], server_ip="127.0.0.1")
