import random


class IEOptions:
    def __init__(self, fp):
        self.R = None
        self.DF = None
        self.DFI = None
        self.T = None
        self.T_MIN = None
        self.T_MAX = None
        self.TG = None
        self.IP_ID = None
        self.CD = None
        self.parse_from_dict(fp)
        
    def compare(self, other_options):
        discrepancies = {}
        if self.R != other_options.R:
            discrepancies["R"] = str(other_options.R) + " should be " + str(self.R)
        if self.DFI != other_options.DFI:
            discrepancies["DFI"] = str(other_options.DFI) + " should be " + str(self.DFI)
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
        if self.CD != other_options.CD:
            discrepancies["CD"] = str(other_options.CD) + " should be " + str(self.CD)
        return {"IE": discrepancies}

    def parse_from_dict(self, fp):
        if "R" in fp:
            self.R = fp["R"]
        if "R" not in fp:
            self.R = 'Y'
        if "DFI" in fp:
            self.DF = fp["DFI"]
            self.DFI = fp["DFI"]
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
        if "II" in fp:
            self.IP_ID = fp["II"]
        if "CD" in fp:
            self.CD = fp["CD"]

    def __str__(self):
        return "IE(" + "R=" + str(self.R) + " DFI=" + str(self.DFI) + " T_MIN=" + str(self.T_MIN) + " T=" + str(self.T) \
               + " T_MAX=" + str(self.T_MAX) + " TG=" + str(self.TG) + " CD=" + str(self.CD) + ")"
