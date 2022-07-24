import random


class UDPOptions:
    def __init__(self, fp):
        self.R = None
        self.DF = None
        self.T = None
        self.T_MIN = None
        self.T_MAX = None
        self.TG = None
        self.IP_ID = None
        self.IPL = None
        self.UN = None
        self.RIPL = None
        self.RID = None
        self.RIPCK = None
        self.POSSIBLE_RIPCK = None
        self.RUCK = None
        self.RUD = None
        self.parse_from_dict(fp)

    def compare(self, other_options):
        discrepancies = {}
        if self.R != other_options.R:
            discrepancies["R"] = str(other_options.R) + " should be " + str(self.R)
        if self.DF != other_options.DF:
            discrepancies["DF"] = str(other_options.DF) + " should be " + str(self.DF)
        if self.T_MIN is not None and self.T_MAX is not None:
            if other_options.T not in range(self.T_MIN, self.T_MAX):
                discrepancies["T"] = str(other_options.T) + " should be in range " + str(
                    self.T_MIN) + "-" + str(
                    self.T_MAX)
        else:
            if self.T != other_options.T:
                discrepancies["T"] = str(other_options.T) + " should be " + str(self.T)
        if self.TG is not None and other_options.TG is not None:
            if self.TG != other_options.TG:
                discrepancies["TG"] = str(other_options.TG) + " should be " + str(self.TG)
        if self.IPL != other_options.IPL:
            discrepancies["IPL"] = str(other_options.IPL) + " should be " + str(self.IPL)
        if self.UN != other_options.UN:
            discrepancies["UN"] = str(other_options.UN) + " should be " + str(self.UN)
        if self.RIPL != other_options.RIPL:
            discrepancies["RIPL"] = str(other_options.RIPL) + " should be " + str(self.RIPL)
        if self.RID != other_options.RID:
            discrepancies["RID"] = str(other_options.RID) + " should be " + str(self.RID)
        if self.POSSIBLE_RIPCK is not None and len(self.POSSIBLE_RIPCK) > 0:
            if other_options.RIPCK not in self.POSSIBLE_RIPCK:
                discrepancies["RIPCK"] = str(other_options.RIPCK) + " should be in" + str(self.POSSIBLE_RIPCK)
        elif self.RIPCK != other_options.RIPCK:
            discrepancies["RIPCK"] = str(other_options.RIPCK) + " should be " + str(self.RIPCK)
        if self.RUCK != other_options.RUCK:
            discrepancies["RUCK"] = str(other_options.RUCK) + " should be " + str(self.RUCK)
        if self.RUD != other_options.RUD:
            discrepancies["RUD"] = str(other_options.RUD) + " should be " + str(self.RUD)
        return {"UDP": discrepancies}

    def parse_from_dict(self, fp):
        if "R" in fp:
            self.R = fp["R"]
        if "R" not in fp:
            self.R = 'Y'
        if "DF" in fp:
            self.DF = fp["DF"]
        if "T" in fp:
            self.T = int(str(fp["T"]), 16)
        if "T_MIN" in fp:
            self.T_MIN = int(str(fp["T_MIN"]), 16)
        if "T_MAX" in fp:
            self.T_MAX = int(str(fp["T_MAX"]), 16)
        if "T_MIN" in fp and "T_MAX" in fp:
            self.T = int(
                int(str(fp["T_MIN"]), 16) + (
                            random.randint(0, pow(2, 32)) % (int(str(fp["T_MAX"]), 16) - int(str(fp["T_MIN"]), 16))))
        if "TG" in fp:
            self.TG = fp["TG"]
        if "IPL" in fp:
            self.IPL = int(fp["IPL"], 16)
        if "TI" in fp:
            self.IP_ID = fp["TI"]
        if "CI" in fp:
            self.IP_ID = fp["CI"]
        if "II" in fp:
            self.IP_ID = fp["II"]
        if "UN" in fp:
            self.UN = fp["UN"]
        if "RIPL" in fp:
            self.RIPL = fp["RIPL"]
        if "RID" in fp:
            self.RID = fp["RID"]
        if "RIPCK" in fp:
            self.RIPCK = fp["RIPCK"]
        if "POSSIBLE_RIPCK" in fp:
            self.POSSIBLE_RIPCK = fp["POSSIBLE_RIPCK"]
        if "RUCK" in fp:
            self.RUCK = fp["RUCK"]
        if "RUD" in fp:
            self.RUD = fp["RUD"]

    def __str__(self):
        return "U1(" + "R=" + str(self.R) + " DF=" + str(self.DF) + " T_MIN=" + str(self.T_MIN) + " T=" + str(self.T) \
               + " T_MAX=" + str(self.T_MAX) + " TG=" + str(self.TG) + " IPL=" + str(self.IPL) + " UN=" + str(self.UN) \
               + " RIPL=" + str(self.RIPL) + " RID=" + str(self.RID) + " RIPCK=" + str(self.RIPCK) + " RUCK=" \
               + str(self.RUCK) + " RUD=" + str(self.RUD) + ")"
