import logging
from datetime import datetime, timedelta

import netifaces as ni
from netifaces import AF_INET

from honey_os.external_ip import ext_IP
from honey_os.session.session_events import SessionEvents

logger = logging.getLogger(__name__)

ext = ext_IP()


class nmap_session(object):
    def __init__(self, ip, time):
        self.ip = ip
        self.time = time
        self.session_events_tcp = SessionEvents()
        self.session_events_udp = SessionEvents()


class Session(object):
    def __init__(self):
        self.sessions = []
        self.my_ip = ext.get_ext_ip()

    def externalIP(self, public, interface):
        if public is True:
            self.my_ip = ext.get_ext_ip()
        else:
            self.my_ip = ni.ifaddresses(interface)[AF_INET][0]["addr"]

    def in_session(self, ip, debug, logger):
        currenttime = datetime.now()
        currenttimestring = currenttime.strftime("%Y-%m-%d %H:%M:%S")
        timeout = currenttime + timedelta(minutes=10)

        for session in self.sessions:
            if ip == session.ip:
                if currenttime > session.time:
                    session.time = timeout
                    # logger.log.debug(
                    #     "%s : Renewed session from %s at %s",
                    #     currenttimestring,
                    #     ip,
                    #     self.my_ip,
                    # )
                    session.session_events_tcp.clear_events()
                    session.session_events_udp.clear_events()
                    if debug:
                        print("renew  " + ip)

                return True

        # print "added"
        nsess = nmap_session(ip, timeout)
        self.sessions.append(nsess)

        # logger.log.debug(
        #     "%s : New session from %s  at %s", currenttimestring, ip, self.my_ip
        # )
        if debug:
            print("new  " + ip)
        return False

    def port_in_session(self, ip, event_type, srcPort, dstPort):
        currenttime = datetime.now()
        currenttimestring = currenttime.strftime("%Y-%m-%d %H:%M:%S")
        timeout = currenttime + timedelta(minutes=10)

        for session in self.sessions:
            if ip == session.ip:
                if currenttime > session.time:
                    session.time = timeout
                    session.session_events_tcp.clear_events()
                    session.session_events_udp.clear_events()
                if event_type == 'unservicedtcp':
                    if session.session_events_tcp.check_if_source_destination_combo_in_session(srcPort, dstPort):
                        if session.session_events_tcp.check_if_source_port_in_session(srcPort) and not session.session_events_tcp.check_if_destination_port_in_session(dstPort):
                            # print("Destination port not in session: %s" % dstPort)
                            # print("Destination ports in session: %s" % session.session_events_tcp.dstPorts)
                            session.session_events_tcp.add_destination_port(dstPort)
                        elif session.session_events_tcp.check_if_destination_port_in_session(dstPort) and not session.session_events_tcp.check_if_source_port_in_session(srcPort):
                            # print("Source port not in session: %s" % srcPort)
                            # print("Source ports in session: %s" % session.session_events_tcp.srcPorts)
                            session.session_events_tcp.add_source_port(srcPort)
                        return True
                    else:
                        if session.session_events_tcp.check_if_source_port_in_session(srcPort):
                            session.session_events_tcp.add_destination_port(dstPort)
                            # print("Destination port not in session: %s" % dstPort)
                            # print("Destination ports in session: %s" % session.session_events_tcp.dstPorts)
                            return True
                        elif session.session_events_tcp.check_if_destination_port_in_session(dstPort):
                            session.session_events_tcp.add_source_port(srcPort)
                            # print("Source port not in session: %s" % srcPort)
                            # print("Source ports in session: %s" % session.session_events_tcp.srcPorts)
                            return True
                        else:
                            # print("Source port and Destination port not in session: %s, %s" % (srcPort, dstPort))
                            # print("Source ports and Destination ports in session: %s, %s" % (session.session_events_tcp.srcPorts, session.session_events_tcp.dstPorts))
                            session.session_events_tcp.add_source_port(srcPort)
                            session.session_events_tcp.add_destination_port(dstPort)
                            return False
                elif event_type == 'unservicedudp':
                    if session.session_events_udp.check_if_source_destination_combo_in_session(srcPort, dstPort):
                        if session.session_events_udp.check_if_source_port_in_session(
                                srcPort) and not session.session_events_udp.check_if_destination_port_in_session(
                                dstPort):
                            # print("Destination port not in session: %s" % dstPort)
                            # print("Destination ports in session: %s" % session.session_events_udp.dstPorts)
                            session.session_events_udp.add_destination_port(dstPort)
                        elif session.session_events_udp.check_if_destination_port_in_session(
                                dstPort) and not session.session_events_udp.check_if_source_port_in_session(srcPort):
                            # print("Source port not in session: %s" % srcPort)
                            # print("Source ports in session: %s" % session.session_events_udp.srcPorts)
                            session.session_events_udp.add_source_port(srcPort)
                        return True
                    else:
                        if session.session_events_udp.check_if_source_port_in_session(srcPort):
                            # print("Destination port not in session: %s" % dstPort)
                            # print("Destination ports in session: %s" % session.session_events_udp.dstPorts)
                            session.session_events_udp.add_destination_port(dstPort)
                            return True
                        elif session.session_events_udp.check_if_destination_port_in_session(dstPort):
                            # print("Source port not in session: %s" % srcPort)
                            # print("Source ports in session: %s" % session.session_events_udp.srcPorts)
                            session.session_events_udp.add_source_port(srcPort)
                            return True
                        else:
                            # print("Source port and Destination port not in session: %s, %s" % (srcPort, dstPort))
                            # print("Source ports and Destination ports in session: %s, %s" % (
                            # session.session_events_udp.srcPorts, session.session_events_udp.dstPorts))
                            session.session_events_udp.add_source_port(srcPort)
                            session.session_events_udp.add_destination_port(dstPort)
                            return False

        # print "added"
        nsess = nmap_session(ip, timeout)
        nsess.session_events_tcp.add_source_port(srcPort)
        nsess.session_events_tcp.add_destination_port(dstPort)
        nsess.session_events_udp.add_source_port(srcPort)
        nsess.session_events_udp.add_destination_port(dstPort)
        #print("Source port and Destination port not in session: %s, %s" % (srcPort, dstPort))
        self.sessions.append(nsess)
        return False
