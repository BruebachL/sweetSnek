#!/usr/bin/python
import hashlib
import json
import random
import threading
import time
from datetime import datetime
from math import log, sqrt

from scapy.all import send  # @UnresolvedImport
from scapy.layers.inet import IP, TCP

import event_logger
from honeypot_event import HoneypotEventDetails, HoneypotEvent, HoneypotEventEncoder, HoneyPotTCPUDPEventContent, \
    HoneyPotNMapScanEventContent
from osfingerprinting.stack_packet.IP_ import ReplyPacket, reverse_crc
from osfingerprinting.stack_packet.OS_pattern_template import get_elapsed_ticks, get_elapsed_time_in_microseconds
from osfingerprinting.stack_packet.helper import forward_packet, drop_packet, print_packet

import logging

logger = logging.getLogger()

# TODO: ... ISR
# TODO: CI

NMAP_PROBE_IP_ATTR = {"T2": {"FLGS": 'DF'}, "T4": {"FLGS": 'DF'}, "T6": {"FLGS": 'DF'}}

# TCP Urgent Pointer in ECN probe
ECN_URGT_PTR = 0xF7F5

WIN_XP_COUNTER = 0

# The TCP Option fields in the Nmap probes
NMAP_PROBE_TCP_OPTION = {
    "P1": [
        ("WScale", 10),
        ("NOP", None),
        ("MSS", 1460),
        ("Timestamp", (4294967295, 0)),
        ("SAckOK", bytes("", "UTF-8")),
    ],
    "P2": [
        ("MSS", 1400),
        ("WScale", 0),
        ("SAckOK", bytes("", "UTF-8")),
        ("Timestamp", (4294967295, 0)),
        ("EOL", None),
    ],
    "P3": [
        ("Timestamp", (4294967295, 0)),
        ("NOP", None),
        ("NOP", None),
        ("WScale", 5),
        ("NOP", None),
        ("MSS", 640),
    ],
    "P4": [
        ("SAckOK", bytes("", "UTF-8")),
        ("Timestamp", (4294967295, 0)),
        ("WScale", 10),
        ("EOL", None),
    ],
    "P5": [
        ("MSS", 536),
        ("SAckOK", bytes("", "UTF-8")),
        ("Timestamp", (4294967295, 0)),
        ("WScale", 10),
        ("EOL", None),
    ],
    "P6": [("MSS", 265), ("SAckOK", bytes("", "UTF-8")), ("Timestamp", (4294967295, 0))],
    "ECN": [
        ("WScale", 10),
        ("NOP", None),
        ("MSS", 1460),
        ("SAckOK", bytes("", "UTF-8")),
        ("NOP", None),
        ("NOP", None),
    ],
    "T2-T6": [
        ("WScale", 10),
        ("NOP", None),
        ("MSS", 265),
        ("Timestamp", (4294967295, 0)),
        ("SAckOK", bytes("", "UTF-8")),
    ],
    "T7": [
        ("WScale", 15),
        ("NOP", None),
        ("MSS", 265),
        ("Timestamp", (4294967295, 0)),
        ("SAckOK", bytes("", "UTF-8")),
    ],
}

# The TCP Window Size and TCP Flags wich have to match
NMAP_PROBE_TCP_ATTR = {
    "P1": {"WSZ": 1, "FLGS": 'S'},
    "P2": {"WSZ": 63, "FLGS": 'S'},
    "P3": {"WSZ": 4, "FLGS": 'S'},
    "P4": {"WSZ": 4, "FLGS": 'S'},
    "P5": {"WSZ": 16, "FLGS": 'S'},
    "P6": {"WSZ": 512, "FLGS": 'S'},
    "ECN": {"WSZ": 3, "FLGS": 0xC2},
    "T2": {"WSZ": 128, "FLGS": ''},
    "T3": {"WSZ": 256, "FLGS": 'FSPU'},
    "T4": {"WSZ": 1024, "FLGS": 'A'},
    "T5": {"WSZ": 31337, "FLGS": 'S'},
    "T6": {"WSZ": 32768, "FLGS": 'A'},
    "T7": {"WSZ": 65535, "FLGS": 'FPU'},
}


def mod_diff(a, b):
    min_val = min(a - b, b - a)
    if min_val >= 0:
        return min_val
    else:
        return -min_val


def process_seq(seq_samples, ts_samples):
    j = 0
    time_usec_diff = 100066
    seq_diffs = [n for n in range((len(seq_samples)))]
    ts_diffs = [n for n in range(len(seq_samples))]
    seq_rates = [n for n in range(len(seq_samples))]
    seq_avg_rate = 0
    for i in range(len(seq_samples) - 1):
        if seq_samples[i] != 0:
            if j < i:
                seq_samples[j] = seq_samples[i]
                ts_samples[j] = ts_samples[i]
            if j > 0:
                seq_diffs[j - 1] = mod_diff(seq_samples[j], seq_samples[j - 1])
                ts_diffs[j - 1] = mod_diff(ts_samples[j], ts_samples[j - 1])
                seq_rates[j - 1] = seq_diffs[j - 1] * 1000000.0 / time_usec_diff  # 9.99340435313 roughly
                seq_avg_rate = seq_avg_rate + seq_rates[j - 1]
            j = j + 1
    return seq_diffs, ts_diffs, seq_rates, seq_avg_rate


def reverse_sp(index, diff_amount):
    seq_stddev = int(index / 8 + 0.5)
    seq_stddev = 2 ** seq_stddev
    seq_stddev = seq_stddev * seq_stddev
    seq_stddev = seq_stddev * diff_amount
    return seq_stddev


def gcd(diffs):
    if len(diffs) == 0:
        return 1
    a = diffs[0]
    for i in range(int(len(diffs) / 2)):
        b = diffs[i + 1]
        if a < b:
            c = a
            a = b
            b = c
        while b:
            c = a % b
            a = b
            b = c
    return a


def sp(sequences, timestamps):
    if len(sequences) > 0:
        seq_diffs, ts_diffs, seq_rates, seq_avg_rate = process_seq(sequences, timestamps)
        if len(seq_diffs) > 1:
            seq_avg_rate = seq_avg_rate / len(seq_diffs)
            seq_rate = seq_avg_rate
            if seq_rate == 0:
                seq_rate = 1
            seq_rate = log(seq_rate) / log(2.0)
            seq_rate = int(seq_rate * 8 + 0.5)
            div_gcd = 1
            seq_stddev = 0
            if gcd(seq_diffs) > 9:
                div_gcd = gcd(seq_diffs)
            for diff in seq_diffs:
                rtmp = diff / div_gcd - seq_avg_rate / div_gcd
                seq_stddev += rtmp * rtmp
            seq_stddev = seq_stddev / (len(seq_diffs) - 1)
            seq_stddev = sqrt(seq_stddev)
            seq_stddev = log(seq_stddev) / log(2)
            index = int(seq_stddev * 8 + 0.5)
            return index
        else:
            return -1
    else:
        return -1


class TCPPacket(ReplyPacket):
    """
    TCP packet
    ----------------------------------------------------------
    setting the TCP fields
    """

    def __init__(self, pkt, os_pattern):
        ReplyPacket.__init__(self, pkt, os_pattern)
        self.pkt = pkt
        self.tcp = TCP()
        self.tcp.sport = pkt[TCP].dport
        self.tcp.dport = pkt[TCP].sport

    def set_tcp_flags(self, flags):
        # set TCP header fields
        if flags is not None:
            self.tcp.flags = flags

    def set_tcp_options(self, pkt, options):
        if options is not None and options != "":
            # calculate Timestamp for TCP header
            print("TCP options: " + str(options.O))
            # self.tcp.options = self.set_timestamp_option(pkt, options)
            self.tcp.options = self.substitute_timestamp(options.O, pkt)

    def set_timestamp_option(self, pkt, options):
        if options.TS_VAL is not None and options.TS_VER is not None:
            if options.TS_VAL == 0 and options.TS_VER == 0:
                if options.O is not None and options.O != "":
                    logger.debug(options.O + [("Timestamp", (int(options.TS_VAL, 10), int(options.TS_VER)))])
                    return options.O + [("Timestamp", (int(options.TS_VAL, 10), int(options.TS_VER)))]
                else:
                    return [("Timestamp", (int(options.TS_VAL, 10), int(options.TS_VER)))]
            # elif options.TS_VAL
        if options.TS is not None:
            if self.os_pattern.seq_options.TS_COUNT == -1:
                if options.O is not None:
                    return options.O
                else:
                    return ""
            ticks = get_elapsed_ticks(self.os_pattern.timer, self.os_pattern.seq_options.TS_COUNT)
            # Round up to make sure we increment
            if self.os_pattern.seq_options.TS_COUNT != 0:
                self.os_pattern.TCP_Timestamp_tmp = self.os_pattern.TCP_Timestamp_tmp + self.os_pattern.seq_options.TS_COUNT / 10
            else:
                self.os_pattern.TCP_Timestamp_tmp = 0  # We know about the timestamp field but don't bother to set it...
            if options.TS_VER is None:
                options.TS_VER = 0
            if options.O is not None and options.O != "":
                return options.O + [
                    ("Timestamp", (int(str(int(self.os_pattern.TCP_Timestamp_tmp)), 10), int(options.TS_VER)))]
            else:
                return [("Timestamp", (int(str(int(self.os_pattern.TCP_Timestamp_tmp)), 10), int(options.TS_VER)))]
        else:
            return options.O

    def substitute_timestamp(self, options, pkt):
        new_options = []
        if options is not None:
            for x in options:
                if x[0] == "Timestamp":
                    if x[1][0] == 1:
                        ticks = get_elapsed_ticks(self.os_pattern.timer, self.os_pattern.seq_options.TS_COUNT)
                        # Round up to make sure we increment
                        if self.os_pattern.seq_options.TS_COUNT != 0:
                            self.os_pattern.TCP_Timestamp_tmp = self.os_pattern.TCP_Timestamp_tmp + self.os_pattern.seq_options.TS_COUNT / 10
                        else:
                            self.os_pattern.TCP_Timestamp_tmp = 0  # We know about the timestamp field but don't bother to set it...
                        x = ("Timestamp", (int(self.os_pattern.TCP_Timestamp_tmp), x[1][1]))
                    if x[1][1] == 1:
                        # Copy TSecr from received packet
                        if TCP in pkt:  # ignore packets without TCP payload
                            for opt, val in pkt[TCP].options:  # consider all TCP options
                                if opt == 'Timestamp':
                                    TSval, TSecr = val  # decode the value of the option
                                    x = ("Timestamp", (x[1][0], int(TSecr)))
                    new_options.append(x)
                else:
                    new_options.append(x)
            return new_options
        else:
            return ""

    # +inline
    # void
    # pers_tcp_next_seq(struct
    # iphdr * iph, struct
    # tcphdr * th,
    # +                             struct
    # ip_pers * pers) {
    #     +  u_int32_t
    # tmp;
    # +
    # +  switch(pers->isn_type) {
    #     +  case
    # IP_PERS_FIXED_INC:
    # +  case
    # IP_PERS_BROKEN_INC:
    # +    pers->current_isn += pers->isn_param;
    # +
    # break;
    # +  case
    # IP_PERS_RAND_INC:
    # +    get_random_bytes( & tmp, sizeof(tmp));
    # +    pers->current_isn += (pers->isn_param ? tmp % pers->isn_param: 0);
    # +
    # break;
    # +  case
    # IP_PERS_RANDOM:
    # +    get_random_bytes( & tmp, sizeof(tmp));
    # +    pers->current_isn = tmp;
    # +
    # break;
    # +  case
    # IP_PERS_BUILTIN:
    # +    pers->current_isn = secure_tcp_sequence_number(iph->daddr, iph->saddr,
    #                                                                      +                                                  th->dest, th->source);
    # +
    # break;
    # +  case
    # IP_PERS_TIME_INC:
    # + if (pers->isn_param > 0)
    # {
    #     +      pers->current_isn += ((jiffies - pers->isn_jiffies)
    #                                  +                          * pers->isn_param) / HZ;
    # +      pers->isn_jiffies = jiffies;
    # +}
    # +
    # break;
    # +  case
    # IP_PERS_ASIS:
    # +  default:
    # +    pers->current_isn = ntohl(th->seq);
    # +
    # break;
    # +}
    # +}
    # +

    # + / * initialize
    # a
    # new
    # mangled
    # connexion * /
    # +void
    # pers_tcp_mangle_seq_new(struct
    # iphdr * iph, struct
    # tcphdr * th,
    # +                            struct
    # ip_pers_conn_info * pci, struct
    # ip_pers * pers) {
    #     +  pers_tcp_next_seq(iph, th, pers);
    # +  pci->seq_offset = pers->current_isn - ntohl(th->seq);
    # +  DEBUGP("PERS:   NEW: Using ISN %u [offset %u] for"
    #           + " %u.%u.%u.%u:%u => %u.%u.%u.%u:%u\n",
    #           +        pers->current_isn, pci->seq_offset,
    #                                            +        NIPQUAD(iph->saddr), ntohs(th->source),
    # +        NIPQUAD(iph->daddr), ntohs(th->dest));
    # +}
    # +

    def set_next_isn(self):

        # if seqn == "O":
        #     pass
        # elif seqn == "A":
        #     self.tcp.seq = self.pkt[TCP].ack
        #
        # elif seqn == "A+":
        #     self.tcp.seq = self.pkt[TCP].ack + 1

        # Get the current timstamp, save it
        time_of_day = datetime.now()

        # If this is our first ISN, then just make one up.
        if self.os_pattern.TCP_SEQ_NR_tmp == 0:
            # self.os_pattern.TCP_SEQ_NR_tmp = random.randint(0, pow(2, 32))
            self.os_pattern.TCP_SEQ_NR_tmp = self.os_pattern.seq_options.GCD
            # self.os_pattern.TCP_SEQ_NR_tmp = 0
            # Save the timeval into the os pattern
            self.os_pattern.initial_ISN = self.os_pattern.TCP_SEQ_NR_tmp
            self.os_pattern.tv_ISN = time_of_day
            return self.os_pattern.TCP_SEQ_NR_tmp

        # if SEQ is constant
        if self.os_pattern.seq_options.ISR < 10:
            # Do nothing
            return self.os_pattern.TCP_SEQ_NR_tmp

        # seconds passed = elapsed_seconds + rest_elapsed_in_microsec /1000000.0
        # seconds_passed = time_diff.tv_sec + ((double)time_diff.tv_usec / 1000000.0);
        time_diff = self.os_pattern.timer_sub(time_of_day, self.os_pattern.tv_ISN)
        time_diff_in_seconds = time_diff.seconds + (time_diff.microseconds / 1000000.0)

        # Nmap saves the values as binary log times 8, so undo this.
        # (Supposedly, Nmap does this to prevent floating point rounding during calculations)
        max = pow(2, (self.os_pattern.seq_options.ISR_MAX / 8)) * time_diff_in_seconds
        min = pow(2, (self.os_pattern.seq_options.ISR_MIN / 8)) * time_diff_in_seconds
        mean = pow(2, (self.os_pattern.seq_options.ISR / 8)) * time_diff_in_seconds
        std_dev = int(pow(2, (self.os_pattern.seq_options.SP / 8)))
        max += (std_dev / 8)
        min -= (std_dev / 8)
        temp = random.randint(0, std_dev)
        ISN_delta = mean

        if self.os_pattern.seq_options.GCD > 9:
            temp *= self.os_pattern.seq_options.GCD
            max += (std_dev / 8) * (self.os_pattern.seq_options.GCD - 1)
            min -= (std_dev / 8) * (self.os_pattern.seq_options.GCD - 1)

        while (max < (mean + temp)) or (min > (mean + temp)):
            temp = random.randint(0, std_dev)
            if self.os_pattern.seq_options.GCD > 9:
                temp *= self.os_pattern.seq_options.GCD

        ISN_delta += temp

        # Only worry about making things line up for the GCD if it's a significant value
        if self.os_pattern.seq_options.GCD > 9:
            GCD_delta = ISN_delta % self.os_pattern.seq_options.GCD
            if GCD_delta > self.os_pattern.seq_options.GCD / 2:
                ISN_delta += self.os_pattern.seq_options.GCD - GCD_delta
            else:
                ISN_delta -= GCD_delta

        self.os_pattern.tv_ISN = time_of_day

        # Avoid sending same Sequence Number twice
        if int(self.os_pattern.TCP_SEQ_NR_tmp) in self.os_pattern.generated_ISNS:
            self.os_pattern.TCP_SEQ_NR_tmp = self.os_pattern.TCP_SEQ_NR_tmp + self.os_pattern.seq_options.GCD
            self.os_pattern.generated_ISNS.append(int(self.os_pattern.TCP_SEQ_NR_tmp))
        else:
            self.os_pattern.generated_ISNS.append(int(self.os_pattern.TCP_SEQ_NR_tmp))
            self.os_pattern.generated_TIMESTAMPS.append(int(self.os_pattern.TCP_Timestamp_tmp))
        self.os_pattern.TCP_SEQ_NR_tmp = (self.os_pattern.TCP_SEQ_NR_tmp + ISN_delta) % (2 ** 32)
        return int(self.os_pattern.TCP_SEQ_NR_tmp)

    def set_next_isn_time(self, options):
        logger.debug("ISN Generation decision")
        if options is not None:
            logger.debug("Options not none: " + str(options))
            if options == 'Z':
                self.tcp.seq = 0
                return
            if options == 'A':
                self.tcp.seq = self.pkt[TCP].ack
                return
            if options == 'A+':
                self.tcp.seq = self.pkt[TCP].ack + 1
                return

        # Get the current timstamp, save it
        time_of_day = datetime.now()
        logger.debug("Generating an isn.")
        # If this is our first ISN, then just make one up.
        if self.os_pattern.isn == 0:
            # self.os_pattern.TCP_SEQ_NR_tmp = random.randint(0, pow(2, 32))
            self.os_pattern.isn = self.os_pattern.seq_options.GCD
            # self.os_pattern.TCP_SEQ_NR_tmp = 0
            # Save the timeval into the os pattern
            self.os_pattern.initial_ISN = self.os_pattern.isn
            self.os_pattern.timer = time_of_day
            self.tcp.seq = self.os_pattern.isn
            return

        # if SEQ is constant
        if self.os_pattern.seq_options.ISR < 10:
            # Do nothing
            self.tcp.seq = self.os_pattern.isn
            return

        elapsed_ticks = get_elapsed_ticks(self.os_pattern.timer, self.os_pattern.seq_options.TS_COUNT)
        elapsed_seconds = int(get_elapsed_time_in_microseconds(self.os_pattern.timer) / 1000) / 1000

        if elapsed_ticks < 0:
            elapsed_ticks = -elapsed_ticks

        logger.debug("elapsed ticks: " + str(elapsed_ticks))
        logger.debug("elapsed seconds: " + str(elapsed_seconds))

        # Nmap saves the values as binary log times 8, so undo this.
        # (Supposedly, Nmap does this to prevent floating point rounding during calculations)
        max = pow(2, (self.os_pattern.seq_options.ISR_MAX / 8)) * elapsed_seconds
        min = pow(2, (self.os_pattern.seq_options.ISR_MIN / 8)) * elapsed_seconds
        mean = pow(2, (self.os_pattern.seq_options.ISR_MIN / 8 + (
                self.os_pattern.seq_options.ISR_MAX / 8 - self.os_pattern.seq_options.ISR_MIN / 8) / 2)) * elapsed_seconds
        std_dev = int(pow(2, (self.os_pattern.seq_options.SP / 8)))
        max += (std_dev / 8)
        min -= (std_dev / 8)
        temp = random.randint(0, std_dev)
        ISN_delta = mean

        if self.os_pattern.seq_options.GCD > 9:
            temp *= self.os_pattern.seq_options.GCD
            max += (std_dev / 8) * (self.os_pattern.seq_options.GCD - 1)
            min -= (std_dev / 8) * (self.os_pattern.seq_options.GCD - 1)

        while (max < (mean + temp)) or (min > (mean + temp)):
            temp = random.randint(0, std_dev)
            if self.os_pattern.seq_options.GCD > 9:
                temp *= self.os_pattern.seq_options.GCD

        ISN_delta = ISN_delta + temp

        # Only worry about making things line up for the GCD if it's a significant value
        if self.os_pattern.seq_options.GCD > 9:
            GCD_delta = ISN_delta % self.os_pattern.seq_options.GCD
            if GCD_delta > self.os_pattern.seq_options.GCD / 2:
                ISN_delta += self.os_pattern.seq_options.GCD - GCD_delta
            else:
                ISN_delta -= GCD_delta

        self.os_pattern.timer = time_of_day

        # Avoid sending same Sequence Number twice
        if int(self.os_pattern.isn) in self.os_pattern.generated_ISNS_2:
            self.os_pattern.isn = self.os_pattern.isn + self.os_pattern.seq_options.GCD
            self.os_pattern.generated_ISNS_2.append(int(self.os_pattern.isn))
        else:
            self.os_pattern.generated_ISNS_2.append(int(self.os_pattern.isn))
        self.os_pattern.isn = int((self.os_pattern.isn + ISN_delta) % 2 ** 32)
        self.tcp.seq = self.os_pattern.isn
        md5_isn = self.generate_md5_isn(self.ip.src, self.tcp.sport, self.ip.dst, self.tcp.dport,
                                        int(self.os_pattern.boot_time_timestamp) & 0xFFFF)
        ticks_and_isn = elapsed_ticks * 4 + md5_isn
        base_time = (self.os_pattern.boot_time * 250000) % 2 ** 32
        lwip_isn = int((md5_isn + base_time + time.monotonic() * 250) % 2 ** 32)

        milliseconds = int(time.time() * 1000)
        self.tcp.seq = lwip_isn
        self.tcp.seq = int(self.os_pattern.get_fictional_isn_timer()) + md5_isn
        # self.tcp.seq = int(ticks_and_isn)
        return

    def generate_md5_isn(self, local_IP, local_port, remote_ip, remote_port, secret_key):
        buffer = bytearray(bytes(local_IP, "UTF-8"))
        buffer.extend(bytearray(bytes(local_port)))
        buffer.extend(bytearray(bytes(remote_ip, "UTF-8")))
        buffer.extend(bytearray(bytes(remote_port)))
        buffer.extend(bytearray(bytes(int(secret_key))))
        hash_md5 = hashlib.md5()
        hash_md5.update(buffer)
        return int(hash_md5.hexdigest(), 16) & 0xFFFF

    # set ack number
    def set_ack_nr(self, ack):
        # to the SEQNr of the probe
        if ack == "S":
            self.tcp.ack = self.pkt[TCP].seq
        # to SEQNr + 1
        elif ack == "S+":
            self.tcp.ack = self.pkt[TCP].seq + 1
        # to a random value
        elif ack == "O":
            self.tcp.ack = random.randint(1, 10)
        # to zero
        elif ack == "Z":
            self.tcp.ack = 0
        else:
            self.tcp.ack = ack

    # set window size
    def set_window_size(self, window_size):
        if window_size is not None:
            self.tcp.window = window_size
        else:
            self.tcp.window = 0

    # (Some operating systems return ASCII data such as error messages in reset packets.)
    def set_tcp_data(self, rd):
        if rd is not None:
            if int(rd) != 0:
                if rd != "":
                    self.tcp.payload = reverse_crc(int(rd))


def send_tcp_reply(pkt, os_pattern, _options):
    tcp_reply = TCPPacket(pkt, os_pattern)  # create reply packet and set flags
    global WIN_XP_COUNTER

    tcp_reply.set_ttl(_options.T)  # set Time-to-live
    tcp_reply.set_tcp_flags(_options.F)  # set flags depending on probe given
    tcp_reply.set_df(_options.DF)  # set/adjust special header fields
    tcp_reply.set_tcp_options(pkt, _options)  # set tcp options and include timestamp if necessary
    os_pattern.tcp_personality_seq()  # prepare timer for isn generation
    # win_xp_seqs = [497630840, 379818574, 2946207896, 1893693727, 4164842625, 1096257183]
    win_xp_seqs = [4164842625, 379818574, 497630840, 1096257183, 1893693727, 2946207896, ]
    # 1096257183,
    # 1893693727,
    # 2946207896,
    # 379818574,
    # 4164842625,
    # 497630840
    if WIN_XP_COUNTER == len(win_xp_seqs):
        tcp_reply.set_next_isn_time(_options.S)  # generate and set sequence number
    else:
        tcp_reply.tcp.seq = win_xp_seqs[WIN_XP_COUNTER]
        WIN_XP_COUNTER = WIN_XP_COUNTER + 1
    tcp_reply.set_ack_nr(_options.A)  # set ack-number
    tcp_reply.set_window_size(_options.W)  # set window size
    tcp_reply.set_ip_id(_options.IP_ID)  # set IP Identity
    tcp_reply.set_tcp_data(_options.RD)  # set TCP data

    send(tcp_reply.ip / tcp_reply.tcp, verbose=0)  # send the TCP packet
    print_packet(tcp_reply.ip / tcp_reply.tcp, True)  # log to file


def check_in_session(session, ip, debug):
    session.in_session(ip, debug)


def check_TCP_Nmap_match(
        pkt, nfq_packet, INPUT_TCP_OPTIONS, EXPECTED_TCP_flags, IP_flags="no", urgt_ptr=0
):
    """
    Check if the packet is a Nmap probe
    IPflags and urgt_ptr are optional
    return 1 if packet is a Nmap probe
    """
    if (
            pkt[TCP].window == EXPECTED_TCP_flags["WSZ"]
            and pkt[TCP].flags == EXPECTED_TCP_flags["FLGS"]
            and pkt[TCP].options == INPUT_TCP_OPTIONS
    ):

        if IP_flags == "no":
            if urgt_ptr == 0:
                drop_packet(nfq_packet)
                report_suspicious_packet(pkt)
                return 1

            elif pkt[TCP].urgptr == ECN_URGT_PTR:
                drop_packet(nfq_packet)
                report_suspicious_packet(pkt)
                return 1

        elif pkt[IP].flags == IP_flags["FLGS"]:
            drop_packet(nfq_packet)
            report_suspicious_packet(pkt)
            return 1

    return 0


def report_suspicious_packet(pkt):
    event = json.dumps(
        HoneypotEvent(HoneypotEventDetails("tcp", HoneyPotTCPUDPEventContent(pkt.src, pkt.sport, pkt.dport))),
        cls=HoneypotEventEncoder, indent=0).replace('\\"', '"').replace('\\n', '\n').replace('}\"', '}').replace(
        '\"{', '{')
    event_logger.EventLogger().async_report_event(event)


def check_TCP_probes(pkt, nfq_packet, os_pattern, session, debug, event_logger):
    # Check TCP Probes
    # Check if the packet is a probe and if a reply should be sent
    # SEQ, OPS, WIN, and T1 - Sequence generation
    # 6 Probes sent
    if check_TCP_Nmap_match(
            pkt, nfq_packet, NMAP_PROBE_TCP_OPTION["P1"], NMAP_PROBE_TCP_ATTR["P1"]
    ):
        logger.debug("TCP Probe #1 detected. Hi Nmap :)")
        print(pkt.src)
        event_logger.ping_back_and_report(pkt.src)
        print_packet(pkt)
        if os_pattern.p1_options is not None and os_pattern.p1_options.R != "N":
            check_in_session(session, pkt.src, debug)
            logger.debug("TCP Probe #1 forged reply sent.")
            logger.debug(os_pattern.p1_options)
            send_tcp_reply(pkt, os_pattern, os_pattern.p1_options)
            os_pattern.generated_TIMESTAMPS.append(int(str(int(os_pattern.TCP_Timestamp_tmp)), 10))
            os_pattern.generated_ISNS_3.append(int(os_pattern.isn))
        else:
            logger.debug("But no reply sent due to OS pattern suppression.")
    elif check_TCP_Nmap_match(
            pkt, nfq_packet, NMAP_PROBE_TCP_OPTION["P2"], NMAP_PROBE_TCP_ATTR["P2"]
    ):
        logger.debug("TCP Probe #2 detected.")
        print_packet(pkt)
        if os_pattern.p2_options is not None and os_pattern.p2_options.R != "N":
            check_in_session(session, pkt.src, debug)
            logger.debug("TCP Probe #2 forged reply sent.")
            logger.debug(os_pattern.p2_options)
            send_tcp_reply(pkt, os_pattern, os_pattern.p2_options)
            os_pattern.generated_TIMESTAMPS.append(int(str(int(os_pattern.TCP_Timestamp_tmp)), 10))
            os_pattern.generated_ISNS_3.append(int(os_pattern.isn))
        else:
            logger.debug("But no reply sent due to OS pattern suppression.")
    elif check_TCP_Nmap_match(
            pkt, nfq_packet, NMAP_PROBE_TCP_OPTION["P3"], NMAP_PROBE_TCP_ATTR["P3"]
    ):
        logger.debug("TCP Probe #3 detected.")
        print_packet(pkt)
        if os_pattern.p3_options is not None and os_pattern.p3_options.R != "N":
            check_in_session(session, pkt.src, debug)
            logger.debug("TCP Probe #3 forged reply sent.")
            logger.debug(os_pattern.p3_options)
            send_tcp_reply(pkt, os_pattern, os_pattern.p3_options)
            os_pattern.generated_TIMESTAMPS.append(int(str(int(os_pattern.TCP_Timestamp_tmp)), 10))
            os_pattern.generated_ISNS_3.append(int(os_pattern.isn))
        else:
            logger.debug("But no reply sent due to OS pattern suppression.")
    elif check_TCP_Nmap_match(
            pkt, nfq_packet, NMAP_PROBE_TCP_OPTION["P4"], NMAP_PROBE_TCP_ATTR["P4"]
    ):
        logger.debug("TCP Probe #4 detected.")
        print_packet(pkt)
        if os_pattern.p4_options is not None and os_pattern.p4_options.R != "N":
            check_in_session(session, pkt.src, debug)
            logger.debug("TCP Probe #4 forged reply sent.")
            logger.debug(os_pattern.p4_options)
            send_tcp_reply(pkt, os_pattern, os_pattern.p4_options)
            os_pattern.generated_TIMESTAMPS.append(int(str(int(os_pattern.TCP_Timestamp_tmp)), 10))
            os_pattern.generated_ISNS_3.append(int(os_pattern.isn))
        else:
            logger.debug("But no reply sent due to OS pattern suppression.")
    elif check_TCP_Nmap_match(
            pkt, nfq_packet, NMAP_PROBE_TCP_OPTION["P5"], NMAP_PROBE_TCP_ATTR["P5"]
    ):
        print_packet(pkt)
        logger.debug("TCP Probe #5 detected.")
        print_packet(pkt)
        if os_pattern.p5_options is not None and os_pattern.p5_options.R != "N":
            check_in_session(session, pkt.src, debug)
            logger.debug("TCP Probe #5 forged reply sent.")
            logger.debug(os_pattern.p5_options)
            send_tcp_reply(pkt, os_pattern, os_pattern.p5_options)
            os_pattern.generated_TIMESTAMPS.append(int(str(int(os_pattern.TCP_Timestamp_tmp)), 10))
            os_pattern.generated_ISNS_3.append(int(os_pattern.isn))
        else:
            logger.debug("But no reply sent due to OS pattern suppression.")

    elif check_TCP_Nmap_match(
            pkt, nfq_packet, NMAP_PROBE_TCP_OPTION["P6"], NMAP_PROBE_TCP_ATTR["P6"]
    ):
        logger.debug("TCP Probe #6 detected.")
        print_packet(pkt)
        if os_pattern.p6_options is not None and os_pattern.p6_options.R != "N":
            check_in_session(session, pkt.src, debug)
            logger.debug("TCP Probe #6 forged reply sent.")
            logger.debug(os_pattern.p6_options)
            send_tcp_reply(pkt, os_pattern, os_pattern.p6_options)
            os_pattern.generated_TIMESTAMPS.append(int(str(int(os_pattern.TCP_Timestamp_tmp)), 10))
            os_pattern.generated_ISNS_3.append(int(os_pattern.isn))
        else:
            logger.debug("But no reply sent due to OS pattern suppression.")

        # SEQ calculation seems to be scuffed so let's see if we can A: Come up with the same results as Nmap
        # and B: reverse engineer those results somehow (maybe have to predict all sequence numbers in advance?)
        logger.debug("First up, here's what it should be.")
        logger.debug(os_pattern.seq_options)
        seq_diffs, ts_diffs, seq_rates, seq_avg_rate = process_seq(os_pattern.generated_ISNS_3,
                                                                   os_pattern.generated_TIMESTAMPS)
        logger.debug("SEQ Numbers: " + str(os_pattern.generated_ISNS_3))
        logger.debug("SEQ Diffs: " + str(seq_diffs))
        logger.debug("TS Diffs: " + str(ts_diffs))
        logger.debug("SEQ Rates: " + str(seq_rates))
        logger.debug("SEQ Avg Rate :" + str(seq_avg_rate))
        logger.debug("SP: " + str(sp(os_pattern.generated_ISNS_3, os_pattern.generated_TIMESTAMPS)))
        logger.debug("TS Avg Hz: " + str(os_pattern.tcp_timestamp_sequence_prediction(ts_diffs)))

    # ECN
    elif check_TCP_Nmap_match(
            pkt,
            nfq_packet,
            NMAP_PROBE_TCP_OPTION["ECN"],
            NMAP_PROBE_TCP_ATTR["ECN"],
    ):
        logger.debug("TCP Probe #ECN detected.")
        print_packet(pkt)
        if os_pattern.ecn_options is not None and os_pattern.ecn_options.R != "N":
            check_in_session(session, pkt.src, debug)
            logger.debug("TCP Probe #ECN forged reply sent.")
            logger.debug(os_pattern.ecn_options)
            send_tcp_reply(pkt, os_pattern, os_pattern.ecn_options)
        else:
            logger.debug("But no reply sent due to OS pattern suppression.")

    # T2-T7
    elif check_TCP_Nmap_match(
            pkt,
            nfq_packet,
            NMAP_PROBE_TCP_OPTION["T2-T6"],
            NMAP_PROBE_TCP_ATTR["T2"],
            NMAP_PROBE_IP_ATTR["T2"],
    ):
        logger.debug("TCP Probe #T2 detected.")
        print_packet(pkt)
        if os_pattern.t2_options is not None and os_pattern.t2_options.R != "N":
            check_in_session(session, pkt.src, debug)
            logger.debug("TCP Probe #T2 forged reply sent.")
            logger.debug(os_pattern.t2_options)
            send_tcp_reply(pkt, os_pattern, os_pattern.t2_options)
        else:
            logger.debug("But no reply sent due to OS pattern suppression.")

    elif check_TCP_Nmap_match(
            pkt, nfq_packet, NMAP_PROBE_TCP_OPTION["T2-T6"], NMAP_PROBE_TCP_ATTR["T3"]
    ):
        logger.debug("TCP Probe #T3 detected.")
        print_packet(pkt)
        if os_pattern.t3_options is not None and os_pattern.t3_options.R != "N":
            check_in_session(session, pkt.src, debug)
            logger.debug("TCP Probe #T3 forged reply sent.")
            logger.debug(os_pattern.t3_options)
            send_tcp_reply(pkt, os_pattern, os_pattern.t3_options)
        else:
            logger.debug("But no reply sent due to OS pattern suppression.")

    elif check_TCP_Nmap_match(
            pkt,
            nfq_packet,
            NMAP_PROBE_TCP_OPTION["T2-T6"],
            NMAP_PROBE_TCP_ATTR["T4"],
            NMAP_PROBE_IP_ATTR["T4"],
    ):
        logger.debug("TCP Probe #T4 detected.")
        print_packet(pkt)
        if os_pattern.t4_options is not None and os_pattern.t4_options.R != "N":
            check_in_session(session, pkt.src, debug)
            logger.debug("TCP Probe #T4 forged reply sent.")
            logger.debug(os_pattern.t4_options)
            send_tcp_reply(pkt, os_pattern, os_pattern.t4_options)
        else:
            logger.debug("But no reply sent due to OS pattern suppression.")

    elif check_TCP_Nmap_match(
            pkt, nfq_packet, NMAP_PROBE_TCP_OPTION["T2-T6"], NMAP_PROBE_TCP_ATTR["T5"]
    ):
        logger.debug("TCP Probe #T5 detected.")
        print_packet(pkt)
        if os_pattern.t5_options is not None and os_pattern.t5_options.R != "N":
            check_in_session(session, pkt.src, debug)
            logger.debug("TCP Probe #T5 forged reply sent.")
            logger.debug(os_pattern.t5_options)
            send_tcp_reply(pkt, os_pattern, os_pattern.t5_options)
        else:
            logger.debug("But no reply sent due to OS pattern suppression.")

    elif check_TCP_Nmap_match(
            pkt,
            nfq_packet,
            NMAP_PROBE_TCP_OPTION["T2-T6"],
            NMAP_PROBE_TCP_ATTR["T6"],
            NMAP_PROBE_IP_ATTR["T6"],
    ):
        logger.debug("TCP Probe #T6 detected.")
        print_packet(pkt)
        if os_pattern.t6_options is not None and os_pattern.t6_options.R != "N":
            check_in_session(session, pkt.src, debug)
            logger.debug("TCP Probe #T6 forged reply sent.")
            logger.debug(os_pattern.t6_options)
            send_tcp_reply(pkt, os_pattern, os_pattern.t6_options)
        else:
            logger.debug("But no reply sent due to OS pattern suppression.")

    elif check_TCP_Nmap_match(
            pkt, nfq_packet, NMAP_PROBE_TCP_OPTION["T7"], NMAP_PROBE_TCP_ATTR["T7"]
    ):
        logger.debug("TCP Probe #T7 detected.")
        print_packet(pkt)
        if os_pattern.t7_options is not None and os_pattern.t7_options.R != "N":
            check_in_session(session, pkt.src, debug)
            logger.debug("TCP Probe #T7 forged reply sent.")
            logger.debug(os_pattern.t7_options)
            send_tcp_reply(pkt, os_pattern, os_pattern.t7_options)
        else:
            logger.debug("But no reply sent due to OS pattern suppression.")

    else:
        forward_packet(nfq_packet)
