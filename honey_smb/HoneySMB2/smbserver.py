import logging
import os

from event_logging.client.logging_client2 import LoggingClient2
from honey_smb.HoneySMB2.libs.smbserver import SMBSERVER
from binascii import unhexlify
import ConfigParser
import sys


class SimpleSMBServer:
    def __init__(self, listenAddress='0.0.0.0', listenPort=445, logging_client=None, configFile=None):
        if configFile == None:
            print("[*] Config File Required")
            sys.exit(0)
        if logging_client == None:
            print("[*] Logging client required.")
            sys.exit(0)
        self.__smbConfig = configFile
        self.log = self.setup_logger("smb_server.log")  # Internal logging, not related to honeypot events.
        self.__server = SMBSERVER((listenAddress, listenPort), logging_client, self.log, config_parser=self.__smbConfig)
        self.__server.processConfigFile()

    def setup_logger(self, log_name):
        if os.path.exists(log_name):
            os.remove(log_name)
        smb_log = logging.Logger(log_name)
        smb_handler = logging.FileHandler(log_name)
        smb_formatter = logging.Formatter(fmt="[%(asctime)s] %(message)-160s (%(module)s:%(funcName)s:%(lineno)d)",
                                             datefmt='%Y-%m-%d %H:%M:%S')
        smb_handler.setFormatter(smb_formatter)
        smb_log.addHandler(smb_handler)
        return smb_log

    def start(self):
        self.__server.serve_forever()

    def registerNamedPipe(self, pipeName, address):
        return self.__server.registerNamedPipe(pipeName, address)

    def unregisterNamedPipe(self, pipeName):
        return self.__server.unregisterNamedPipe(pipeName)

    def getRegisteredNamedPipes(self):
        return self.__server.getRegisteredNamedPipes()

    def addShare(self, shareName, sharePath, shareComment='', shareType=0, readOnly='no'):
        self.__smbConfig.add_section(shareName)
        self.__smbConfig.set(shareName, 'comment', shareComment)
        self.__smbConfig.set(shareName, 'read only', readOnly)
        self.__smbConfig.set(shareName, 'share type', shareType)
        self.__smbConfig.set(shareName, 'path', sharePath)
        self.__server.setServerConfig(self.__smbConfig)
        self.__server.processConfigFile()

    def removeShare(self, shareName):
        self.__smbConfig.remove_section(shareName)
        self.__server.setServerConfig(self.__smbConfig)
        self.__server.processConfigFile()

    def setSMBChallenge(self, challenge):
        if challenge != '':
            self.__smbConfig.set('global', 'challenge', unhexlify(challenge))
            self.__server.setServerConfig(self.__smbConfig)
            self.__server.processConfigFile()

    def setLogFile(self, logFile):
        self.__smbConfig.set('global', 'log_file', logFile)
        self.__server.setServerConfig(self.__smbConfig)
        self.__server.processConfigFile()

    def setCredentialsFile(self, credFile):
        self.__smbConfig.set('global', 'credentials_file', credFile)
        self.__server.setServerConfig(self.__smbConfig)
        self.__server.processConfigFile()

    def setSMB2Support(self, value):
        if value is True:
            self.__smbConfig.set("global", "SMB2Support", "True")
        else:
            self.__smbConfig.set("global", "SMB2Support", "False")
        self.__server.setServerConfig(self.__smbConfig)
        self.__server.processConfigFile()


def main():
    logging_client = LoggingClient2("SMB")
    smbConfig = ConfigParser.RawConfigParser()
    smbConfig.read('smb.conf')
    smbServer = SimpleSMBServer(logging_client=logging_client, configFile=smbConfig)

    shareConfig = ConfigParser.RawConfigParser()
    shareConfig.read("shares.conf")

    shareNames = [i.strip() for i in shareConfig.get('shareNames', 'share_names').split(',')]
    for shareName in shareNames:
        comment = shareConfig.get(shareName, 'comment')
        readOnly = shareConfig.get(shareName, 'read_only')
        shareType = shareConfig.get(shareName, 'share_type')
        path = shareConfig.get(shareName, 'path')
        smbServer.addShare(shareName=shareName, sharePath=path, shareComment=comment, shareType=shareType,
                           readOnly=readOnly)
        smbServer.setSMB2Support(True);
    try:
        smbServer.start()
    except Exception as e:
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
