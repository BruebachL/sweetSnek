import random


class ECNOptions:
    def __init__(self, fp):
        self.R = None
        self.DF = None
        # TODO: T sometimes messes up. Win 7
        self.T = None
        self.T_MIN = None
        self.T_MAX = None
        self.TG = None
        self.W = None
        self.O = None
        self.TS = None
        self.TS_VAL = None
        self.TS_VER = None
        self.IP_ID = None
        self.S = None
        self.A = None
        self.F = None
        self.RD = None
        self.Q = None
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
        if self.W != other_options.W:
            discrepancies["W"] = str(other_options.W) + " should be " + str(self.W)
        if self.O != other_options.O:
            discrepancies["O"] = str(other_options.O) + " should be " + str(self.O)
        if self.S != other_options.S:
            discrepancies["S"] = str(other_options.S) + " should be " + str(self.S)
        if self.A != other_options.A:
            discrepancies["A"] = str(other_options.A) + " should be " + str(self.A)
        if self.F != other_options.F:
            discrepancies["F"] = str(other_options.F) + " should be " + str(self.F)
        if self.RD != other_options.RD:
            discrepancies["RD"] = str(other_options.RD) + " should be " + str(self.RD)
        if self.Q != other_options.Q:
            discrepancies["Q"] = str(other_options.Q) + " should be " + str(self.Q)
        return {"ECN": discrepancies}

    def parse_from_dict(self, fp):
        if "R" in fp:
            self.R = fp["R"]
        if "DF" in fp:
            self.DF = fp["DF"]
        if "T" in fp:
            self.T = int(fp["T"], 16)
        if "T_MIN" in fp:
            self.T_MIN = int(str(fp["T_MIN"]), 16)
        if "T_MAX" in fp:
            self.T_MAX = int(str(fp["T_MAX"]), 16)
        if "T_MIN" in fp and "T_MAX" in fp:
            self.T = int(
                self.T_MIN + (random.randint(0, pow(2, 32)) % (self.T_MAX - self.T_MIN)))
        if "TG" in fp:
            self.TG = fp["TG"]
        if "W" in fp:
            self.W = int(fp["W"], 16)
        if "O" in fp:
            self.O = fp["O"]
        if "TS" in fp:
            self.TS = fp["TS"]
            if fp["TS"] == "U":
                self.TS_COUNT = -1
            elif fp["TS"] == "0":
                self.TS_COUNT = 0
            elif fp["TS"] == "1":
                self.TS_COUNT = random.randint(0, 5)
            elif fp["TS"] == "7":
                self.TS_COUNT = random.randint(70, 150)
            elif fp["TS"] == "8":
                self.TS_COUNT = random.randint(150, 350)
            else:
                # round(log2(average increments per second)) = A
                self.TS_COUNT = 2048  # Most common result
        if "tsval" in fp:
            self.TS_VAL = fp["tsval"]
        if "tsver" in fp:
            self.TS_VER = fp["tsver"]
        if "TI" in fp:
            self.IP_ID = fp["TI"]
        if "CI" in fp:
            self.IP_ID = fp["CI"]
        if "S" in fp:
            self.S = fp["S"]
        if "A" in fp:
            self.A = fp["A"]
        if "F" in fp:
            self.F = fp["F"]
        if "RD" in fp:
            self.RD = fp["RD"]
        if "Q" in fp:
            self.Q = fp["Q"]

    def __str__(self):
        return "ECN(" + "R=" + str(self.R) + " DF=" + str(self.DF) + " T=" + str(self.T) + " TG=" + str(self.TG) \
               + " W=" + str(self.W) + " O=" + str(self.O) + " S=" + str(self.S) + " A=" + str(self.A) + " F=" \
               + str(self.F) + " RD=" + str(self.RD) + " Q=" + str(self.Q) + ")"
