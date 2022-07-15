class WINOptions:
    def __init__(self, fp):
        self.R = None
        self.W1 = None
        self.W2 = None
        self.W3 = None
        self.W4 = None
        self.W5 = None
        self.W6 = None
        self.parse_from_dict(fp)

    def compare(self, other_options):
        discrepancies = {}
        if self.R != other_options.R:
            discrepancies["R"] = str(other_options.R) + " should be " + str(self.R)
        if self.W1 != other_options.W1:
            discrepancies["W1"] = str(other_options.W1) + " should be " + str(self.W1)
        if self.W2 != other_options.W2:
            discrepancies["W2"] = str(other_options.W2) + " should be " + str(self.W2)
        if self.W3 != other_options.W3:
            discrepancies["W3"] = str(other_options.W3) + " should be " + str(self.W3)
        if self.W4 != other_options.W4:
            discrepancies["W4"] = str(other_options.W4) + " should be " + str(self.W4)
        if self.W5 != other_options.W5:
            discrepancies["W5"] = str(other_options.W5) + " should be " + str(self.W5)
        if self.W6 != other_options.W6:
            discrepancies["W6"] = str(other_options.W6) + " should be " + str(self.W6)
        return {"WIN": discrepancies}

    def parse_from_dict(self, fp):
        if "R" in fp:
            self.R = fp["R"]
        if "W1" in fp:
            self.W1 = int(fp["W1"], 16)
        if "W2" in fp:
            self.W2 = int(fp["W2"], 16)
        if "W3" in fp:
            self.W3 = int(fp["W3"], 16)
        if "W4" in fp:
            self.W4 = int(fp["W4"], 16)
        if "W5" in fp:
            self.W5 = int(fp["W5"], 16)
        if "W6" in fp:
            self.W6 = int(fp["W6"], 16)

    def __str__(self):
        return "WIN(" + "R=" + str(self.R) + " W1=" + str(self.W1) + " W2=" + str(self.W2) + " W3=" + str(self.W3) \
               + " W4=" + str(self.W4) + " W5=" + str(self.W5) + " W6=" + str(self.W6) + ")"
