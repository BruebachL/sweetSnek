#!/usr/bin/python
"""
Created on 24.09.2016
@author: manuel
"""

from scapy.layers.inet import IP, UDP  # @UnresolvedImport
from scapy.layers.netbios import NBNSQueryRequest, NBNSQueryResponse, \
    NBNSNodeStatusResponse, NBNSNodeStatusResponseService, NBNSWackResponse, NBTDatagram, \
    NBTSession

from osfingerprinting.stack_packet.ICMP_ import send_ICMP_reply
from osfingerprinting.stack_packet.helper import drop_packet, forward_packet


def check_UDP_probe(pkt, nfq_packet, os_pattern):
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
        print("U1 Probe dropped.")
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
