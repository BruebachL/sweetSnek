class SessionEvents:

    def __init__(self, srcPorts=None, dstPorts=None):
        if srcPorts is None:
            srcPorts = []
        else:
            self.srcPorts = srcPorts
        if dstPorts is None:
            dstPorts = []
        else:
            self.dstPorts = dstPorts

    def add_source_port(self, srcPort):
        self.srcPorts.append(srcPort)

    def add_destination_port(self, dstPort):
        self.dstPorts.append(dstPort)

    def check_if_source_port_in_session(self, srcPort):
        if srcPort in self.srcPorts:
            return True
        else:
            return False

    def check_if_destination_port_in_session(self, dstPort):
        if dstPort in self.dstPorts:
            return True
        else:
            return False

    def check_if_source_destination_combo_in_session(self, srcPort, dstPort):
        if self.check_if_source_port_in_session(srcPort) or self.check_if_destination_port_in_session(dstPort):
            return True
        else:
            return False

    def clear_events(self):
        self.srcPorts = []
        self.dstPorts = []
