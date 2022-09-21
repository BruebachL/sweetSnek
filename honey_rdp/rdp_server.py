import argparse
import datetime
import sys

from rdpy.core import rss, log
from rdpy.protocol.rdp import rdp
from twisted.internet import reactor

from honey_log.client.logging_client2 import LoggingClient2
from honey_log.honeypot_event import HoneyPotLoginEventContent

logging_client = LoggingClient2("RDP")


class HoneyPotServer(rdp.RDPServerObserver):
    def __init__(self, client_ip, controller, rssFileSizeList):
        """
        @param controller: {RDPServerController}
        @param rssFileSizeList: {Tuple} Tuple(Tuple(width, height), rssFilePath)
        """
        rdp.RDPServerObserver.__init__(self, controller)
        self._rssFileSizeList = rssFileSizeList
        self.client_ip = client_ip
        self._dx, self._dy = 0, 0
        self._rssFile = None

    def onReady(self):
        """
        @summary:  Event use to inform state of server stack
                    First time this event is called is when human client is connected
                    Second time is after color depth nego, because color depth nego
                    restart a connection sequence
        @see: rdp.RDPServerObserver.onReady
        """
        if self._rssFile is None:
            # compute which RSS file to keep
            width, height = self._controller.getScreen()
            size = width * height
            rssFilePath = sorted(self._rssFileSizeList, key=lambda x: abs(x[0][0] * x[0][1] - size))[0][1]
            log.info("%s --- select file (%s, %s) -> %s" % (
            datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%fZ'), width, height, rssFilePath))
            self._rssFile = rss.createReader(rssFilePath)

        domain, username, password = self._controller.getCredentials()
        print(str(self.client_ip))
        if username == "":
            username = "No Username"
        if password == "":
            password = "No Password"
        logging_client.report_event("login", HoneyPotLoginEventContent(str(self.client_ip), "RDP", username, password))
        hostname = self._controller.getHostname()
        log.info("""%s --- Credentials: domain: %s username: %s password: %s hostname: %s""" % (
        datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%fZ'), domain, username, password, hostname));
        self.start()

    def onClose(self):
        """ HoneyPot """

    def onKeyEventScancode(self, code, isPressed, isExtended):
        """ HoneyPot """

    def onKeyEventUnicode(self, code, isPressed):
        """ HoneyPot """

    def onPointerEvent(self, x, y, button, isPressed):
        """ HoneyPot """

    def start(self):
        self.loopScenario(self._rssFile.nextEvent())

    def loopScenario(self, nextEvent):
        """
        @summary: main loop event
        """
        if nextEvent.type.value == rss.EventType.UPDATE:
            self._controller.sendUpdate(nextEvent.event.destLeft.value + self._dx,
                                        nextEvent.event.destTop.value + self._dy,
                                        nextEvent.event.destRight.value + self._dx,
                                        nextEvent.event.destBottom.value + self._dy, nextEvent.event.width.value,
                                        nextEvent.event.height.value, nextEvent.event.bpp.value,
                                        nextEvent.event.format.value == rss.UpdateFormat.BMP,
                                        nextEvent.event.data.value)

        #elif nextEvent.type.value == rss.EventType.CLOSE:
            #self._controller.close()
            #return

        elif nextEvent.type.value == rss.EventType.SCREEN:
            self._controller.setColorDepth(nextEvent.event.colorDepth.value)
            # compute centering because we cannot resize client
            clientSize = nextEvent.event.width.value, nextEvent.event.height.value
            serverSize = self._controller.getScreen()

            self._dx, self._dy = (max(0, serverSize[0] - clientSize[0]) / 2), max(0,
                                                                                  (serverSize[1] - clientSize[1]) / 2)
            # restart connection sequence
            return

        e = self._rssFile.nextEvent()
        reactor.callLater(float(e.timestamp.value) / 1000.0, lambda: self.loopScenario(e))


class HoneyPotServerFactory(rdp.ServerFactory):
    """
    @summary: Factory on listening events
    """

    def __init__(self, rssFileSizeList, privateKeyFilePath, certificateFilePath):
        """
        @param rssFileSizeList: {Tuple} Tuple(Tuple(width, height), rssFilePath)
        @param privateKeyFilePath: {str} file contain server private key (if none -> back to standard RDP security)
        @param certificateFilePath: {str} file contain server certificate (if none -> back to standard RDP security)
        """
        rdp.ServerFactory.__init__(self, 16, privateKeyFilePath, certificateFilePath)
        self._rssFileSizeList = rssFileSizeList

    def buildObserver(self, controller, addr):
        """
        @param controller: {rdp.RDPServerController}
        @param addr: destination address
        @see: rdp.ServerFactory.buildObserver
        """
        log.info("%s --- Connection from %s:%s" % (
        datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%fZ'), addr.host, addr.port))
        return HoneyPotServer(addr.host, controller, self._rssFileSizeList)


def readSize(filePath):
    """
    @summary: read size event in rss file
    @param filePath: path of rss file
    """
    r = rss.createReader(filePath)
    while True:
        e = r.nextEvent()
        if e is None:
            return None
        elif e.type.value == rss.EventType.SCREEN:
            return e.event.width.value, e.event.height.value


def start_server(bind, port, interaction_mode, rss_size_file, private_key_file, certificate_file):
    from twisted.internet import reactor
    rssFileSizeList = []
    print("What")
    size = readSize(rss_size_file)
    rssFileSizeList.append((size, rss_size_file))
    log.info("%s --- (%s, %s) -> %s" % (
    datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%fZ'), size[0], size[1], rss_size_file))

    reactor.listenTCP(port, HoneyPotServerFactory(rssFileSizeList, private_key_file, certificate_file))
    reactor.run()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Run an RDP honeypot server')
    parser.add_argument("--port", "-p", help="The port to bind the RDP server to (default 3389)", default=3389,
                        type=int,
                        action="store")
    parser.add_argument("--bind", "-b", help="The address to bind the RDP server to", default="", type=str,
                        action="store")
    parser.add_argument("--rss-size-file", "-r", help="The path to the RSS Size List File", default="/home/ascor/PycharmProjects/sweetSnek/honey_rdp/20220921203806_127.0.0.1_1.rss", type=str,
                        action="store")
    parser.add_argument("--private-key-file", "-k", help="The path to the Private Key File", default="key.pem", type=str,
                        action="store")
    parser.add_argument("--certificate-file", "-c", help="The path to the Certificate File", default="cert.pem", type=str,
                        action="store")
    parser.add_argument("--high-interaction", "-hi",
                        help="High interactive (Accept all auths, give them a login vnc session) mode",
                        action="store_true")
    parser.add_argument("--low-interaction", "-li", help="Low interactive (Reject all auths) mode", action="store_true")
    args = parser.parse_args()
    low_interaction_mode = True
    if args.high_interaction and args.low_interaction:
        print(
            "Can't start RDP Server in both high and low interactive mode. Please only choose one of --high-interaction or --low-interaction")
        sys.exit(1)
    elif not args.high_interaction and not args.low_interaction:
        print("No mode (high/low) selected, defaulting to (safer) low.")
    elif args.high_interaction and not args.low_interaction:
        low_interaction_mode = False
    start_server(args.bind, args.port, False, args.rss_size_file, args.private_key_file, args.certificate_file)
