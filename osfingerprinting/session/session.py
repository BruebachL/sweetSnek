from datetime import datetime, timedelta
import logging
from netifaces import AF_INET, AF_INET6, AF_LINK, AF_PACKET, AF_BRIDGE
import netifaces as ni

import event_logger
from osfingerprinting.external_ip import ext_IP

logger = logging.getLogger("oschameleon")

ext = ext_IP()


class nmap_session(object):
    def __init__(self, ip, time):
        self.ip = ip
        self.time = time


class Session(object):
    def __init__(self):
        self.sessions = []
        self.my_ip = ext.get_ext_ip()

    def externalIP(self, public, interface):
        if public is True:
            self.my_ip = ext.get_ext_ip()
        else:
            self.my_ip = ni.ifaddresses(interface)[AF_INET][0]["addr"]

    def in_session(self, ip, debug):
        currenttime = datetime.now()
        currenttimestring = currenttime.strftime("%Y-%m-%d %H:%M:%S")
        timeout = currenttime + timedelta(minutes=10)

        exists = False

        for session in self.sessions:
            if ip == session.ip:
                exists = True
                if currenttime > session.time:
                    session.time = timeout
                    logger.info(
                        "%s : Renewed session from %s at %s",
                        currenttimestring,
                        ip,
                        self.my_ip,
                    )
                    if debug:
                        print("renew  " + ip)

        if not exists:
            # print "added"
            nsess = nmap_session(ip, timeout)
            self.sessions.append(nsess)
            event_logger.EventLogger().ping_back_and_report(ip)
            logger.info(
                "%s : New session from %s  at %s", currenttimestring, ip, self.my_ip
            )
            if debug:
                print("new  " + ip)
