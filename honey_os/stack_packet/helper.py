#!/usr/bin/python
import logging
import os
from datetime import datetime

log = logging.getLogger(__name__)


def flush_tables():
    os.system("iptables -F")


def forward_packet(nfq_packet):
    # send the packet from NFQUEUE without modification
    nfq_packet.accept()


def drop_packet(nfq_packet):
    # drop the packet from NFQUEUE
    nfq_packet.drop()


def get_packet_layers(packet):
    counter = 0
    while True:
        layer = packet.getlayer(counter)
        if layer is None:
            break

        yield layer
        counter += 1


def get_packet_layer_names(packet):
    counter = 0
    while True:
        layer = packet.getlayer(counter)
        if layer is None:
            break

        yield layer.name
        counter += 1


def print_packet(packet, sending=False):
    layers = list(get_packet_layers(packet))
    layer_names = list(get_packet_layer_names(packet))
    if sending:
        log.debug(f'{" >>>>>>>>>>>>>>>>>>":20}' + f'{datetime.now().strftime("%d.%m.%Y %H:%M:%S"):30}' + f'{"":20}')
    else:
        log.debug(
            f'{"":20}' + f'{datetime.now().strftime("%d.%m.%Y %H:%M:%S"):30}' + f'{" <<<<<<<<<<<<<<<<<<":20}')
    if "IP" in layer_names:
        log.debug("IP Header:")
        log.debug(f'{"":20}' + f'{"src: ":30}' + str(layers[layer_names.index("IP")].src))
        log.debug(f'{"":20}' + f'{"dst: ":30}' + str(layers[layer_names.index("IP")].dst))
        log.debug(f'{"":20}' + f'{"ihl: ":30}' + str(layers[layer_names.index("IP")].ihl))
        log.debug(f'{"":20}' + f'{"tos: ":30}' + str(layers[layer_names.index("IP")].tos))
        log.debug(f'{"":20}' + f'{"len: ":30}' + str(layers[layer_names.index("IP")].len))
        log.debug(f'{"":20}' + f'{"id: ":30}' + str(layers[layer_names.index("IP")].id))
        log.debug(f'{"":20}' + f'{"flags: ":30}' + str(layers[layer_names.index("IP")].flags))
        log.debug(f'{"":20}' + f'{"frag: ":30}' + str(layers[layer_names.index("IP")].frag))
        log.debug(f'{"":20}' + f'{"ttl: ":30}' + str(layers[layer_names.index("IP")].ttl))
        log.debug(f'{"":20}' + f'{"proto: ":30}' + str(layers[layer_names.index("IP")].proto))
        log.debug(f'{"":20}' + f'{"chksum: ":30}' + str(layers[layer_names.index("IP")].chksum))
        log.debug(f'{"":20}' + f'{"options: ":30}' + str(layers[layer_names.index("IP")].options))
        log.debug("")

    if "TCP" in layer_names:
        log.debug("TCP Header:")
        log.debug(f'{"":20}' + f'{"sport:":30}' + str(layers[layer_names.index("TCP")].sport))
        log.debug(f'{"":20}' + f'{"dport:":30}' + str(layers[layer_names.index("TCP")].dport))
        log.debug(f'{"":20}' + f'{"seq:":30}' + str(layers[layer_names.index("TCP")].seq))
        log.debug(f'{"":20}' + f'{"ack:":30}' + str(layers[layer_names.index("TCP")].ack))
        log.debug(f'{"":20}' + f'{"dataofs:":30}' + str(layers[layer_names.index("TCP")].dataofs))
        log.debug(f'{"":20}' + f'{"reserved:":30}' + str(layers[layer_names.index("TCP")].reserved))
        log.debug(f'{"":20}' + f'{"flags:":30}' + str(layers[layer_names.index("TCP")].flags))
        log.debug(f'{"":20}' + f'{"window:":30}' + str(layers[layer_names.index("TCP")].window))
        log.debug(f'{"":20}' + f'{"chksum:":30}' + str(layers[layer_names.index("TCP")].chksum))
        log.debug(f'{"":20}' + f'{"urgptr:":30}' + str(layers[layer_names.index("TCP")].urgptr))
        log.debug(f'{"":20}' + f'{"options:":30}' + str(layers[layer_names.index("TCP")].options))
        log.debug("")

    if "UDP" in layer_names:
        log.debug("UDP Header:")
        log.debug(f'{"":20}' + f'{"sport:":30}' + str(layers[layer_names.index("UDP")].sport))
        log.debug(f'{"":20}' + f'{"dport:":30}' + str(layers[layer_names.index("UDP")].dport))
        log.debug(f'{"":20}' + f'{"len:":30}' + str(layers[layer_names.index("UDP")].len))
        log.debug(f'{"":20}' + f'{"chksum:":30}' + str(layers[layer_names.index("UDP")].chksum))
        log.debug("")

    if "ICMP" in layer_names:
        log.debug("ICMP Header:")
        log.debug(f'{"":20}' + f'{"type:":30}' + str(layers[layer_names.index("ICMP")].type))
        log.debug(f'{"":20}' + f'{"code:":30}' + str(layers[layer_names.index("ICMP")].code))
        log.debug(f'{"":20}' + f'{"chksum:":30}' + str(layers[layer_names.index("ICMP")].chksum))
        log.debug(f'{"":20}' + f'{"id:":30}' + str(layers[layer_names.index("ICMP")].id))
        log.debug(f'{"":20}' + f'{"seq:":30}' + str(layers[layer_names.index("ICMP")].seq))
        log.debug(f'{"":20}' + f'{"ts_ori:":30}' + str(layers[layer_names.index("ICMP")].ts_ori))
        log.debug(f'{"":20}' + f'{"ts_rx:":30}' + str(layers[layer_names.index("ICMP")].ts_rx))
        log.debug(f'{"":20}' + f'{"ts_tx:":30}' + str(layers[layer_names.index("ICMP")].ts_tx))
        log.debug(f'{"":20}' + f'{"gw:":30}' + str(layers[layer_names.index("ICMP")].gw))
        log.debug(f'{"":20}' + f'{"ptr:":30}' + str(layers[layer_names.index("ICMP")].ptr))
        log.debug(f'{"":20}' + f'{"reserved:":30}' + str(layers[layer_names.index("ICMP")].reserved))
        log.debug(f'{"":20}' + f'{"length:":30}' + str(layers[layer_names.index("ICMP")].length))
        log.debug(f'{"":20}' + f'{"addr_mask:":30}' + str(layers[layer_names.index("ICMP")].addr_mask))
        log.debug(f'{"":20}' + f'{"nexthopmtu:":30}' + str(layers[layer_names.index("ICMP")].nexthopmtu))
        log.debug(f'{"":20}' + f'{"unused:":30}' + str(layers[layer_names.index("ICMP")].unused))
        log.debug("")


def rules(server):
    # print server
    # allow incoming ssh
    os.system(
        "iptables -A INPUT -p tcp -s "
        + server
        + " --dport 63712 -m state --state NEW,ESTABLISHED -j ACCEPT"
    )
    os.system(
        "iptables -A OUTPUT -p tcp -d "
        + server
        + " --sport 63712 -m state --state ESTABLISHED -j ACCEPT"
    )

    # allow outgoing ssh
    os.system(
        "iptables -A OUTPUT -p tcp -d "
        + server
        + " --sport 63712 -m state --state NEW,ESTABLISHED -j ACCEPT"
    )
    os.system(
        "iptables -A INPUT -p tcp -s "
        + server
        + " --dport 63712 -m state --state ESTABLISHED -j ACCEPT"
    )

    # allow incoming internal logging
    os.system(
        "iptables -A INPUT -p tcp -s "
        + server
        + " --dport 6000 -m state --state NEW,ESTABLISHED -j ACCEPT"
    )
    os.system(
        "iptables -A OUTPUT -p tcp -d "
        + server
        + " --sport 6000 -m state --state ESTABLISHED -j ACCEPT"
    )

    # allow outgoing internal logging
    os.system(
        "iptables -A OUTPUT -p tcp -d "
        + server
        + " --sport 6000 -m state --state NEW,ESTABLISHED -j ACCEPT"
    )
    os.system(
        "iptables -A INPUT -p tcp -s "
        + server
        + " --dport 6000 -m state --state ESTABLISHED -j ACCEPT"
    )

    # allow incoming SMB
    os.system(
        "iptables -A INPUT -p tcp -s "
        + server
        + " --dport 139 -m state --state NEW,ESTABLISHED -j ACCEPT"
    )
    os.system(
        "iptables -A OUTPUT -p tcp -d "
        + server
        + " --sport 139 -m state --state ESTABLISHED -j ACCEPT"
    )

    # allow outgoing SMB
    os.system(
        "iptables -A OUTPUT -p tcp -d "
        + server
        + " --sport 139 -m state --state NEW,ESTABLISHED -j ACCEPT"
    )
    os.system(
        "iptables -A INPUT -p tcp -s "
        + server
        + " --dport 139 -m state --state ESTABLISHED -j ACCEPT"
    )

    # allow incoming SMB
    os.system(
        "iptables -A INPUT -p tcp -s "
        + server
        + " --dport 445 -m state --state NEW,ESTABLISHED -j ACCEPT"
    )
    os.system(
        "iptables -A OUTPUT -p tcp -d "
        + server
        + " --sport 445 -m state --state ESTABLISHED -j ACCEPT"
    )

    # allow outgoing SMB
    os.system(
        "iptables -A OUTPUT -p tcp -d "
        + server
        + " --sport 445 -m state --state NEW,ESTABLISHED -j ACCEPT"
    )
    os.system(
        "iptables -A INPUT -p tcp -s "
        + server
        + " --dport 445 -m state --state ESTABLISHED -j ACCEPT"
    )

    # allow incoming HoneyPot FTP
    os.system(
        "iptables -A INPUT -p tcp -s "
        + server
        + " --dport 21 -m state --state NEW,ESTABLISHED -j ACCEPT"
    )
    os.system(
        "iptables -A OUTPUT -p tcp -d "
        + server
        + " --sport 21 -m state --state ESTABLISHED -j ACCEPT"
    )

    # allow outgoing HoneyPot FTP
    os.system(
        "iptables -A OUTPUT -p tcp -d "
        + server
        + " --sport 21 -m state --state NEW,ESTABLISHED -j ACCEPT"
    )
    os.system(
        "iptables -A INPUT -p tcp -s "
        + server
        + " --dport 21 -m state --state ESTABLISHED -j ACCEPT"
    )

    os.system(
        "iptables -A INPUT -p tcp -s "
        + server
        + " --dport 21 -m state --state ESTABLISHED -j ACCEPT"
    )

    # allow incoming HoneyPot SSH
    os.system(
        "iptables -A INPUT -p tcp -s "
        + server
        + " --dport 22 -m state --state NEW,ESTABLISHED -j ACCEPT"
    )
    os.system(
        "iptables -A OUTPUT -p tcp -d "
        + server
        + " --sport 22 -m state --state ESTABLISHED -j ACCEPT"
    )

    # allow outgoing HoneyPot SSH
    os.system(
        "iptables -A OUTPUT -p tcp -d "
        + server
        + " --sport 22 -m state --state NEW,ESTABLISHED -j ACCEPT"
    )
    os.system(
        "iptables -A INPUT -p tcp -s "
        + server
        + " --dport 22 -m state --state ESTABLISHED -j ACCEPT"
    )

    os.system(
        "iptables -A INPUT -p tcp -s "
        + server
        + " --dport 22 -m state --state ESTABLISHED -j ACCEPT"
    )

    # allow incoming HTTP
    os.system(
        "iptables -A INPUT -p tcp -s "
        + server
        + " --dport 80 -m state --state NEW,ESTABLISHED -j ACCEPT"
    )
    os.system(
        "iptables -A OUTPUT -p tcp -d "
        + server
        + " --sport 80 -m state --state ESTABLISHED -j ACCEPT"
    )

    # allow outgoing HTTP
    os.system(
        "iptables -A OUTPUT -p tcp -d "
        + server
        + " --sport 80 -m state --state NEW,ESTABLISHED -j ACCEPT"
    )
    os.system(
        "iptables -A INPUT -p tcp -s "
        + server
        + " --dport 80 -m state --state ESTABLISHED -j ACCEPT"
    )
    
    os.system(
        "iptables -A INPUT -p tcp -s "
        + server
        + " --dport 80 -m state --state ESTABLISHED -j ACCEPT"
    )
    
    # allow incoming Elastic
    os.system(
        "iptables -A INPUT -p tcp -s "
        + server + " -d " + server
        + " --dport 9200 -m state --state NEW,ESTABLISHED -j ACCEPT"
    )
    os.system(
        "iptables -A OUTPUT -p tcp -d "
        + server + " -d " + server
        + " --sport 9200 -m state --state ESTABLISHED -j ACCEPT"
    )

    # allow outgoing Elastic
    os.system(
        "iptables -A OUTPUT -p tcp -d "
        + server + " -d " + server
        + " --sport 9200 -m state --state NEW,ESTABLISHED -j ACCEPT"
    )
    os.system(
        "iptables -A INPUT -p tcp -s "
        + server + " -d " + server
        + " --dport 9200 -m state --state ESTABLISHED -j ACCEPT"
    )
    
    # allow incoming Kibana
    os.system(
        "iptables -A INPUT -p tcp -s "
        + server
        + " --dport 5601 -m state --state NEW,ESTABLISHED -j ACCEPT"
    )
    os.system(
        "iptables -A OUTPUT -p tcp -d "
        + server
        + " --sport 5601 -m state --state ESTABLISHED -j ACCEPT"
    )

    # allow outgoing Kibana
    os.system(
        "iptables -A OUTPUT -p tcp -d "
        + server
        + " --sport 5601 -m state --state NEW,ESTABLISHED -j ACCEPT"
    )
    os.system(
        "iptables -A INPUT -p tcp -s "
        + server
        + " --dport 5601 -m state --state ESTABLISHED -j ACCEPT"
    )

    # allow incoming Logstash
    os.system(
        "iptables -A INPUT -p tcp -s "
        + server
        + " --dport 5044 -m state --state NEW,ESTABLISHED -j ACCEPT"
    )
    os.system(
        "iptables -A OUTPUT -p tcp -d "
        + server
        + " --sport 5044 -m state --state ESTABLISHED -j ACCEPT"
    )

    # allow outgoing Logstash
    os.system(
        "iptables -A OUTPUT -p tcp -d "
        + server
        + " --sport 5044 -m state --state NEW,ESTABLISHED -j ACCEPT"
    )
    os.system(
        "iptables -A INPUT -p tcp -s "
        + server
        + " --dport 5044 -m state --state ESTABLISHED -j ACCEPT"
    )

    # Configure NFQUEUE target
    # Capture incoming packets and put in nfqueue 1
    os.system("iptables -A INPUT -j NFQUEUE --queue-num 0")
    os.system("iptables -A INPUT -p udp -j NFQUEUE --queue-num 1")
