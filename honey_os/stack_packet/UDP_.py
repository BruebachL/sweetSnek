#!/usr/bin/python
"""
Created on 24.09.2016
@author: manuel
"""
import json

from scapy.layers.inet import IP, UDP  # @UnresolvedImport
from scapy.layers.netbios import NBNSQueryRequest, NBNSQueryResponse, \
    NBNSNodeStatusResponse, NBNSNodeStatusResponseService, NBNSWackResponse, NBTDatagram, \
    NBTSession

from honey_log.honeypot_event import HoneypotEvent, HoneyPotTCPUDPEventContent, HoneypotEventEncoder, \
    HoneypotEventDetails
from honey_os.stack_packet.ICMP_ import send_ICMP_reply
from honey_os.stack_packet.helper import drop_packet, forward_packet


def report_suspicious_packet(pkt, logging_client):
    event = json.dumps(
        HoneypotEvent(HoneypotEventDetails("udp", HoneyPotTCPUDPEventContent(pkt.src, pkt.sport, pkt.dport))),
        cls=HoneypotEventEncoder, indent=0).replace('\\"', '"').replace('\\n', '\n').replace('}\"', '}').replace(
        '\"{', '{')
    logging_client.output_buffer.append(bytes(event, 'UTF-8'))

def check_UDP_probe(pkt, nfq_packet, logging_client, os_pattern):
    """
    Identify the UDP based probe
    and reply with a faked reply if needed
    """
    probe_payload = b'C' * 300
    if (
            pkt[IP].id == 0x1042
            and probe_payload == bytes(pkt[UDP].payload)
    ):
        drop_packet(nfq_packet)
        report_suspicious_packet(pkt, logging_client)
        print("U1 Probe dropped.")
        #event = json.dumps(HoneypotEvent(HoneypotEventDetails("tcp", HoneyPotTCPUDPEventContent("127.0.0.2", "1111", "2222"))), cls=HoneypotEventEncoder, indent=0).replace('\\"', '"').replace('\\n', '\n').replace('}\"', '}').replace('\"{', '{')
        #logger.async_report_event(event)
        if os_pattern.u1_options is not None and os_pattern.u1_options.R != "N":
            # create reply packet (ICMP port unreachable)
            # ICMP type = 3  =^ destination unreachable
            ICMP_type = 3
            send_ICMP_reply(pkt, ICMP_type, os_pattern, os_pattern.u1_options)
            print("U1 Probe spoofed reply sent.")
        else:
            print("But no U1 Probe ICMP Reply sent due to OS pattern suppression.")
    elif pkt[UDP].dport == 137:
        print("NBT Broadcast")
        #print(pkt[UDP].payload)
        match pkt[UDP].payload:
            case NBNSQueryRequest():
                print("Query request received.")
            case NBNSQueryResponse():
                print("NBNS Query Response received.")
            case NBNSNodeStatusResponse():
                print("NBNS Node Status Response received.")
            case NBNSNodeStatusResponseService():
                print("NBNS Node Status Response Service received.")
            case NBNSWackResponse():
                print("NBNS Wait for Acknowledgement Response received.")
            case NBTDatagram():
                print("NBT Datagram Packet received.")
            case NBTSession():
                print("NBT Session Packet received.")
        forward_packet(nfq_packet)
    else:
        forward_packet(nfq_packet)
