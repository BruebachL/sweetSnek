import random

from osfingerprinting.parsing_helper import hex_int


class SEQOptions:
    def __init__(self, fp):
        # SP (standard deviation of Initial SEQNr)
        self.SP_MIN = None
        self.SP_MAX = None
        self.SP = None
        # GCD Greatest common divisor
        self.POSSIBLE_GCD = []
        self.GCD_MIN = None
        self.GCD = None
        self.GCD_MAX = None
        # ISR Initial SEQNr counter rate
        self.ISR_MIN = None
        self.ISR_MAX = None
        self.ISR = None
        # TI - CI - II IP ID sequence generation algorithm
        # difference of IP header ID fields by different response groups
        #  I (incremental)
        #  RI (random positive increments)
        #  BI (broken increment)
        self.TI = None
        self.CI = None
        self.II = None
        # Shared IP ID sequence Boolean
        self.SS = None
        # TCP timestamp option algorithm
        self.TS = None
        self.TS_COUNT = None
        self.parse_from_fingerprint(fp)
        
    def compare(self, other_options):
        discrepancies = {}
        if self.SP_MIN is not None and self.SP_MAX is not None:
            if other_options.SP not in range(self.SP_MIN, self.SP_MAX+1):
                discrepancies["SP"] = str(other_options.SP) + " should be in range " \
                                      + str(self.SP_MIN) + "-" + str(self.SP_MAX)
        else:
            if self.SP != other_options.SP:
                discrepancies["SP"] = str(other_options.SP) + " should be " + str(self.SP)
        if len(self.POSSIBLE_GCD) > 1:
            if other_options.GCD not in self.POSSIBLE_GCD:
                discrepancies["GCD"] = str(other_options.GCD) + " should be in " + str(self.POSSIBLE_GCD)
        else:
            if self.GCD_MIN is not None and self.GCD_MAX is not None:
                if other_options.GCD not in range(self.GCD_MIN, self.GCD_MAX):
                    discrepancies["GCD"] = str(other_options.GCD) + " should be in range " \
                                          + str(self.GCD_MIN) + "-" + str(self.GCD_MAX)
            elif self.GCD != other_options.GCD:
                discrepancies["GCD"] = str(other_options.GCD) + " should be " + str(self.GCD)
        if self.ISR_MIN is not None and self.ISR_MAX is not None:
            if other_options.ISR not in range(self.ISR_MIN, self.ISR_MAX + 1):
                discrepancies["ISR"] = str(other_options.ISR) + " should be in range " + str(self.ISR_MIN) + "-" \
                                       + str(self.ISR_MAX)
        else:
            if self.ISR != other_options.ISR:
                discrepancies["ISR"] = str(other_options.ISR) + " should be " + str(self.ISR)
        if self.TI != other_options.TI:
            discrepancies["TI"] = str(other_options.TI) + " should be " + str(self.TI)
        if self.CI != other_options.CI:
            discrepancies["CI"] = str(other_options.CI) + " should be " + str(self.CI)
        if self.II != other_options.II:
            discrepancies["II"] = str(other_options.II) + " should be " + str(self.II)
        if self.SS != other_options.SS:
            discrepancies["SS"] = str(other_options.SS) + " should be " + str(self.SS)
        if self.TS != other_options.TS:
            discrepancies["TS"] = str(other_options.TS) + " should be " + str(self.TS)
        return {"SEQ": discrepancies}

    def parse_from_fingerprint(self, fp):
        if "SP" in fp:
            self.SP = int(fp["SP"], 16)
        if "SP_MIN" in fp:
            self.SP_MIN = int(fp["SP_MIN"], 16)
        if "SP_MAX" in fp:
            self.SP_MAX = int(fp["SP_MAX"], 16)
        if "SP_MIN" in fp and "SP_MAX" in fp:
            self.SP = min(self.SP_MIN, self.SP_MAX)
        if "GCD" in fp:
            self.GCD = int(fp["GCD"], 16)
        if "GCD_MIN" in fp:
            self.GCD_MIN = int(fp["GCD_MIN"], 16)
        if "GCD_MAX" in fp:
            self.GCD_MAX = int(fp["GCD_MAX"], 16)
        if "GCD_MIN" in fp and "GCD_MAX" in fp:
            self.GCD = min(self.GCD_MIN, self.GCD_MAX)
        if "POSSIBLE_GCD" in fp:
            self.POSSIBLE_GCD = list(map(hex_int, fp["POSSIBLE_GCD"]))
            self.GCD = min(self.POSSIBLE_GCD)
        if "ISR" in fp:
            self.ISR = int(fp["ISR"], 16)
        if "ISR_MIN" in fp:
            self.ISR_MIN = int(fp["ISR_MIN"], 16)
        if "ISR_MAX" in fp:
            self.ISR_MAX = int(fp["ISR_MAX"], 16)
        if "ISR_MIN" in fp and "ISR_MAX" in fp:
            self.ISR = int(int(fp["ISR_MIN"], 16) + (int(fp["ISR_MAX"], 16) - int(fp["ISR_MIN"], 16))/2)
        if "TI" in fp:
            self.TI = fp["TI"]
        if "CI" in fp:
            self.CI = fp["CI"]
        if "II" in fp:
            self.II = fp["II"]
        if "SS" in fp:
            self.SS = fp["SS"]
        if "TS" in fp:
            self.TS = fp["TS"]
            if fp["TS"] == "U":
                self.TS_COUNT = -1
            elif fp["TS"] == "0":
                self.TS_COUNT = 0
            elif fp["TS"] == "1":
                #self.TS_COUNT = random.randint(0, 5)
                self.TS_COUNT = 1
            elif fp["TS"] == "7":
                #self.TS_COUNT = random.randint(70, 150)
                self.TS_COUNT = 70 + (150 - 70) / 2
            elif fp["TS"] == "8":
                #self.TS_COUNT = random.randint(150, 350)
                self.TS_COUNT = 150 + (350 - 150) / 2
            elif fp["TS"] == "A":
                # round(log2(average increments per second)) = A
                self.TS_COUNT = 1000  # Most common result
            else:
                self.TS_COUNT = 1000  # Most common result

    def __str__(self):
        return "SEQ(" + "SP=" + str(self.SP) + " GCD=" + str(self.GCD) + " ISR_MIN=" + str(self.ISR_MIN) \
               + " ISR=" + str(self.ISR) + " ISR_MAX=" + str(self.ISR_MAX) + " TI=" + str(self.TI) + " CI=" \
               + str(self.CI) + " II=" + str(self.II) + " SS=" + str(self.SS) + " TS=" + str(self.TS) + ")"
