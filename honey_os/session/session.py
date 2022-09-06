import logging
from datetime import datetime, timedelta

import netifaces as ni
from netifaces import AF_INET

from honey_os.external_ip import ext_IP

logger = logging.getLogger(__name__)

ext = ext_IP()


class nmap_session(object):
    def __init__(self, ip, time):
        self.ip = ip
        self.time = time
        self.reported_events = []


class Session(object):
    def __init__(self):
        self.sessions = []
        self.my_ip = ext.get_ext_ip()

    def externalIP(self, public, interface):
        if public is True:
            self.my_ip = ext.get_ext_ip()
        else:
            self.my_ip = ni.ifaddresses(interface)[AF_INET][0]["addr"]

    def in_session(self, ip, debug, logger, type):
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
                    session.reported_events = []
                    if debug:
                        print("renew  " + ip)
                if type in session.reported_events:
                    return True
                else:
                    session.reported_events.append(type)
                    return False

        # print "added"
        nsess = nmap_session(ip, timeout)
        nsess.reported_events.append(type)
        self.sessions.append(nsess)

        # logger.log.debug(
        #     "%s : New session from %s  at %s", currenttimestring, ip, self.my_ip
        # )
        if debug:
            print("new  " + ip)
        return False
