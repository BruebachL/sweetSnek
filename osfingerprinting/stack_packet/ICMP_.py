#!/usr/bin/python

"""
Created on 24.09.2016
@author: manuel
"""
import json

from scapy.fields import RawVal

import event_logger
from honeypot_event import HoneypotEventDetails, HoneypotEvent, HoneyPotICMPEventContent, HoneypotEventEncoder
from osfingerprinting.stack_packet.IP_ import ReplyPacket
from scapy.all import send, Padding  # @UnresolvedImport
from scapy.layers.inet import IP, ICMP, UDP
from osfingerprinting.stack_packet.helper import forward_packet, drop_packet, print_packet


class ICMPPacket(ReplyPacket):
    """
    ICMP packet
    """

    def __init__(self, pkt, os_pattern, package_type):
        ReplyPacket.__init__(self, pkt, os_pattern)
        self.icmp = ICMP()
        self.pkt = pkt
        # self.pkt.ttl = self.os_pattern.TTL

        # type = 0 ^= echo reply
        if package_type == 0:
            self.icmp.type = 0
            self.icmp.id = pkt[ICMP].id
            self.icmp.seq = pkt[ICMP].seq
            self.data = pkt[ICMP].payload
        # type = 3 & code = 3 ^= port unreachable
        elif package_type == 3:
            self.icmp.type = 3
            self.icmp.code = 3
            self.icmp.unused = os_pattern.UN

    def set_ICMP_code(self, icmpc):
        self.icmp.code = icmpc

    def set_dfi(self, options):
        match options:
            case "Y":
                self.ip.flags = "DF"
            case "N":
                self.ip.flags = ""
            case "S":
                self.ip.flags = self.pkt["IP"].flags
            case "O":
                if self.pkt["IP"].flags == 0x40:
                    pass
                else:
                    self.ip.flags = 0x40



    def set_checksum(self, options):
        match options:
            case "G":
                # Because we fiddle with the returned IP Packets TTL,
                # we have to set its checksum to the enclosing packets checksum.
                # Since the returned IP Packets checksum doesn't matter to routers, an invalid one is fine.
                self.pkt["IP"].chksum = self.ip.chksum
            case "Z":
                self.ip.chksum = 0
            case "I":
                self.ip.chksum = 1337
        # self.ip.show()  # Force scapy to recalculate so the value sticks...

    def set_udp_checksum(self, options):
        if options is not None and options != "G":
            self.pkt["UDP"].chksum = int(options)

    def set_packet_ttl(self, ttl):
        if ttl > 255:  # Ensure we get bumped up to Nmap's next TTL guess bracket if the value is unreasonable.
            if self.pkt["IP"].ttl <= 32:
                self.pkt["IP"].ttl = 32 + (-(self.pkt["IP"].ttl - 32)) + 1
            elif self.pkt["IP"].ttl <= 64:
                self.pkt["IP"].ttl = 64 + (-(self.pkt["IP"].ttl - 64)) + 1
            elif self.pkt["IP"].ttl <= 128:
                self.pkt["IP"].ttl = 128 + (-(self.pkt["IP"].ttl - 128)) + 1
            else:
                self.pkt["IP"].ttl = 255

    def set_unused_messaged_header_bytes(self, options):
        if options is not None and options != 0:
            # Scapy is confused and thinks the unused bytes in the header belong to nexthopmtu...
            if '>' not in str(options) and '<' not in str(options):
                self.icmp.setfieldval("nexthopmtu", int(str(options), 16))
            elif '>' in str(options):
                self.icmp.setfieldval("nexthopmtu", int(str(options.replace('>', '')), 16) + 1)
            elif '<' in str(options):
                self.icmp.setfieldval("nexthopmtu", int(str(options.replace('<', '')), 16) - 1)

    # some OSes reply with no data returned
    def clr_payload(self):
        self.pkt[UDP].remove_payload()

    # echo reply
    def send_packet(self):
        send(self.ip / self.icmp / self.data, verbose=0)

    # port unreachable
    def send_PUR_packet(self):
        send(self.ip / self.icmp / self.pkt, verbose=0)


def send_ICMP_reply(pkt, ICMP_type, os_pattern, _options):
    """
    Send ICMP reply packet
    """
    # create reply packet and set flags
    icmp_rpl = ICMPPacket(pkt, os_pattern, ICMP_type)
    print("ICMP Type: " + str(ICMP_type) + " TTL = " + str(_options.T))
    icmp_rpl.set_ttl(_options.T)

    # set ICMP header fields
    icmp_rpl.set_df(_options.DF)

    # ICMP type = 0  =^ echo reply
    if ICMP_type == 0:
        icmp_rpl.set_ip_id(_options.IP_ID)
        icmp_rpl.set_dfi(_options.DFI)
        # set ICMP code field
        if _options.CD == "S":
            icmp_rpl.set_ICMP_code(pkt[ICMP].code)
        elif _options.CD == "Z":
            icmp_rpl.set_ICMP_code(0)
        else:
            icmp_rpl.set_ICMP_code(_options.CD)

        # send ICMP reply
        icmp_rpl.send_packet()

    # ICMP type = 3  =^ destination unreachable
    elif ICMP_type == 3:
        icmp_rpl.set_ip_id(_options.IP_ID)
        # Checksum gets corrupted if we fiddle with TTL so ensure setting this first.
        if _options.T > 255:
            icmp_rpl.set_packet_ttl(_options.T)
        icmp_rpl.set_checksum(_options.RIPCK)
        icmp_rpl.set_udp_checksum(_options.RUCK)
        print(_options.RIPCK)
        icmp_rpl.set_unused_messaged_header_bytes(_options.UN)
        # some OS reply with no data returned
        if _options.RUD == "G" and 328 > _options.IPL:
            icmp_rpl.clr_payload()

        len_packet = int(str(len(icmp_rpl.pkt)), 16)
        if len_packet < _options.IPL:
            print("icmp input packet length: ", len_packet)
            pad_len = _options.IPL - len_packet - 16
            pad = Padding()
            pad.add_payload("\x00" * pad_len)
            icmp_rpl.pkt = icmp_rpl.pkt / pad
            print("icmp reply packet length: ", int(str(len(icmp_rpl.pkt)), 16))
            # icmp_rpl.pkt["IP"].len = _options.IPL


        # send ICMP Port Unreachable
        icmp_rpl.send_PUR_packet()
    print_packet(icmp_rpl.ip / icmp_rpl.icmp, True)


def report_suspicious_packet(pkt):
    event = json.dumps(
        HoneypotEvent(HoneypotEventDetails("icmp", HoneyPotICMPEventContent(pkt.src, pkt.type, pkt.code))),
        cls=HoneypotEventEncoder, indent=0).replace('\\"', '"').replace('\\n', '\n').replace('}\"', '}').replace(
        '\"{', '{')
    event_logger.EventLogger().async_report_event(event)


def check_ICMP_probes(pkt, nfq_packet, os_pattern):
    """
    Identify the ICMP based probes
    and reply with a faked packet if needed
    """
    if pkt[ICMP].type == 8:
        # Probe 1 + 2
        if (
                pkt[ICMP].seq == 295
                and pkt[IP].flags == 0x02
                and len(pkt[ICMP].payload) == 120
        ) or (
                pkt[ICMP].seq == 296
                and pkt[IP].tos == 0x04
                and len(pkt[ICMP].payload) == 150
        ):
            drop_packet(nfq_packet)
            report_suspicious_packet(pkt)
            print("IE Probe dropped.")
            if os_pattern.ie_options is not None and os_pattern.ie_options.R != "N":
                # ICMP type = 0  =^ echo reply
                ICMP_type = 0
                send_ICMP_reply(pkt, ICMP_type, os_pattern, os_pattern.ie_options)
                print("IE Probe spoofed reply sent.")
            else:
                print("But no IE Probe ICMP reply sent due to OS pattern suppression.")
        else:
            forward_packet(nfq_packet)
    else:
        forward_packet(nfq_packet)
