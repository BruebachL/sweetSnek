class OPSOptions:
    def __init__(self, fp):
        self.R = None
        self.O1 = None
        self.O2 = None
        self.O3 = None
        self.O4 = None
        self.O5 = None
        self.O6 = None
        self.parse_from_dict(fp)
        
    def compare(self, other_options):
        discrepancies = {}
        if self.R != other_options.R:
            discrepancies["R"] = str(other_options.R) + " should be " + str(self.R)
        if self.O1 != other_options.O1:
            discrepancies["O1"] = str(other_options.O1) + " should be " + str(self.O1)
        if self.O2 != other_options.O2:
            discrepancies["O2"] = str(other_options.O2) + " should be " + str(self.O2)
        if self.O3 != other_options.O3:
            discrepancies["O3"] = str(other_options.O3) + " should be " + str(self.O3)
        if self.O4 != other_options.O4:
            discrepancies["O4"] = str(other_options.O4) + " should be " + str(self.O4)
        if self.O5 != other_options.O5:
            discrepancies["O5"] = str(other_options.O5) + " should be " + str(self.O5)
        if self.O6 != other_options.O6:
            discrepancies["O6"] = str(other_options.O6) + " should be " + str(self.O6)
        return {"OPS": discrepancies}

    def parse_from_dict(self, fp):
        if "R" in fp:
            self.R = fp["R"]
        if "O1" in fp:
            self.O1 = fp["O1"]
        if "O2" in fp:
            self.O2 = fp["O2"]
        if "O3" in fp:
            self.O3 = fp["O3"]
        if "O4" in fp:
            self.O4 = fp["O4"]
        if "O5" in fp:
            self.O5 = fp["O5"]
        if "O6" in fp:
            self.O6 = fp["O6"]

    def __str__(self):
        return "OPS(" + "R=" + str(self.R) + " O1=" + str(self.O1) + " O2=" + str(self.O2) + " O3=" + str(self.O3) \
               + " O4=" + str(self.O4) + " O5=" + str(self.O5) + " O6=" + str(self.O6) + ")"
