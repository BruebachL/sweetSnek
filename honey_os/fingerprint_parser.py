import inspect
import random
import re
from time import sleep

from honey_os.parsing_helper import _upper_end_hex
from honey_os.process import Process
from honey_os.stack_packet.OS_pattern_template import OSPatternTemplate
from honey_os.stack_packet.options.ECN_options import ECNOptions
from honey_os.stack_packet.options.IE_options import IEOptions
from honey_os.stack_packet.options.OPS_options import OPSOptions
from honey_os.stack_packet.options.SEQ_options import SEQOptions
from honey_os.stack_packet.options.TCP_options import TCPOptions
from honey_os.stack_packet.options.UDP_options import UDPOptions
from honey_os.stack_packet.options.WIN_options import WINOptions
from honey_os.template.os_templates import template_list

# TODO:
""""
ISR
TS   not correct
SP incorrect because of ISR and TS
CHECK IF CI TI AND II ARE *USED* CORRECTLY
SS
A
"""


# Parses an options set, returns a random value in the set, and the set.
def parse_options_set(key, options_set):
    possible_values = options_set.split("|")
    if key == "GCD":  # Choose the lowest GCD to help with ISN calculation
        return min(possible_values), possible_values
    else:
        return random.choice(possible_values), possible_values


# TODO: Remove _str2int and separate parsing from assignment
# Parses an options range, returns the minimum value in the range and the maximum value.
def parse_options_range(options_range):
    minVal, maxVal = options_range.split("-")
    return minVal, maxVal


# Parse a single key-value pair, taking into account sets, ranges, and possible special handling.
def parse_key_value(fp, category, key, value):
    if category == "SEQ" and (key == "TS" or key == "TI"):
        fp = generate_probes_in_dict(fp)
        fp[category][key] = value
        fp["P1"][key] = value
        fp["P2"][key] = value
        fp["P3"][key] = value
        fp["P4"][key] = value
        fp["P5"][key] = value
        fp["P6"][key] = value
        return fp
    if category == "SEQ" and key == "CI":
        if "T5" not in fp:
            fp["T5"] = dict()
        if "T6" not in fp:
            fp["T6"] = dict()
        if "T7" not in fp:
            fp["T7"] = dict()
        fp[category][key] = value
        fp["T5"][key] = value
        fp["T6"][key] = value
        fp["T7"][key] = value
        return fp
    if category == "SEQ" and key == "II":
        if "IE" not in fp:
            fp["IE"] = dict()
        fp["IE"][key] = value
        return fp
    if category == "T1":
        return split_tcp_reply(fp, category, key, value)
    if key == "O":  # TCP Options need to be parsed differently
        return parse_tcp_option(fp, category, value)
    if "|" in value:  # e.g. GCD=FA7F|1F4FE|2EF7D|3E9FC|4E47B
        chosen_value, possible_values = parse_options_set(key, value)
        fp[category][key] = chosen_value
        fp[category]["POSSIBLE_" + key] = possible_values
    elif "-" in value:  # e.g. SP=0-5
        min_value, max_value = parse_options_range(value)
        fp[category][key + "_MIN"] = min_value
        fp[category][key + "_MAX"] = max_value
    else:
        fp[category][key] = value
    return fp


# Parse all key values in given line.
def parse_key_value_pairs(fp, category, key_values):
    for key_value in key_values.split("%"):
        key, value = key_value.split("=")
        fp = parse_key_value(fp, category, key, value)
    return fp


# Split the window options among Probe 1-6.
def parse_window_options(fp, category, key_values):
    key_value_pairs = key_values.split("%")
    if "R=N" in key_value_pairs:
        fp["WIN"]["R"] = "N"
        if "P5" not in fp:
            fp["P5"] = dict()
        if "P6" not in fp:
            fp["P6"] = dict()
        fp["P5"]["R"] = "N"
        fp["P6"]["R"] = "N"
        return fp
    for i in range(len(key_value_pairs)):
        key, value = key_value_pairs[i].split("=")
        if "P" + str(i + 1) not in fp:
            fp["P" + str(i + 1)] = dict()
        fp = parse_key_value(fp, category, key, value)
        fp = parse_key_value(fp, "P" + str(i + 1), "W", value)
    return fp


def generate_probes_in_dict(fp):
    if "P1" not in fp:
        fp["P1"] = dict()
    if "P2" not in fp:
        fp["P2"] = dict()
    if "P3" not in fp:
        fp["P3"] = dict()
    if "P4" not in fp:
        fp["P4"] = dict()
    if "P5" not in fp:
        fp["P5"] = dict()
    if "P6" not in fp:
        fp["P6"] = dict()
    return fp


# Split the rest of the T1 options among Probe 1-6.
def split_tcp_reply(fp, category, key, value):
    fp = generate_probes_in_dict(fp)
    if "|" in value:  # e.g. GCD=FA7F|1F4FE|2EF7D|3E9FC|4E47B
        chosen_value, possible_values = parse_options_set(key, value)
        fp[category][key] = chosen_value
        fp["P1"][key] = chosen_value
        fp["P2"][key] = chosen_value
        fp["P3"][key] = chosen_value
        fp["P4"][key] = chosen_value
        fp["P5"][key] = chosen_value
        fp["P6"][key] = chosen_value
        fp[category]["POSSIBLE_" + key] = possible_values
        fp["P1"]["POSSIBLE_" + key] = possible_values
        fp["P2"]["POSSIBLE_" + key] = possible_values
        fp["P3"]["POSSIBLE_" + key] = possible_values
        fp["P4"]["POSSIBLE_" + key] = possible_values
        fp["P5"]["POSSIBLE_" + key] = possible_values
        fp["P6"]["POSSIBLE_" + key] = possible_values
    elif "-" in value:  # e.g. SP=0-5
        min_value, max_value = parse_options_range(value)
        fp[category][key + "_MIN"] = min_value
        fp["P1"][key + "_MIN"] = min_value
        fp["P2"][key + "_MIN"] = min_value
        fp["P3"][key + "_MIN"] = min_value
        fp["P4"][key + "_MIN"] = min_value
        fp["P5"][key + "_MIN"] = min_value
        fp["P6"][key + "_MIN"] = min_value
        fp[category][key + "_MAX"] = max_value
        fp["P1"][key + "_MAX"] = max_value
        fp["P2"][key + "_MAX"] = max_value
        fp["P3"][key + "_MAX"] = max_value
        fp["P4"][key + "_MAX"] = max_value
        fp["P5"][key + "_MAX"] = max_value
        fp["P6"][key + "_MAX"] = max_value
    else:
        fp[category][key] = value
        fp["P1"][key] = value
        fp["P2"][key] = value
        fp["P3"][key] = value
        fp["P4"][key] = value
        fp["P5"][key] = value
        fp["P6"][key] = value

    return fp


# Splits a tcp option line into appropriate decoded probe options and timestamp.
def split_tcp_option(value):
    current_probe = []
    timestamp = []

    for ch in range(len(value)):
        ans = 0

        # MSS
        if value[ch] == "M":
            upper = _upper_end_hex(value, ch + 1)
            ans = value[ch + 1: upper]
            # int('0x' + string, 16)
            ans = int("0x" + ans, 16)
            current_probe.append(("MSS", ans))
        # NOP
        if value[ch] == "N":
            current_probe.append(("NOP", 0))
        # EOL
        if value[ch] == "L":
            current_probe.append(("EOL", 0))
        # Window size
        if value[ch] == "W":
            upper = _upper_end_hex(value, ch + 1)
            ans = int(value[ch + 1: upper], 16)
            current_probe.append(("WScale", ans))
        # Timestamp
        if value[ch] == "T":
            ans = value[ch + 1: ch + 3]
            tsval = value[ch + 1: ch + 2]
            tsver = value[ch + 2: ch + 3]
            # timestamp.append(('Timestamp', (str(tsval+tsver))))
            #timestamp.append(tsval)
            #timestamp.append(tsver)
            current_probe.append(("Timestamp", (int(tsval), int(tsver))))
        # selective ack permitted
        if value[ch] == "S":
            current_probe.append(("SAckOK", ""))

    return current_probe, timestamp


def parse_tcp_option(fp, category, value):
    if value == "":
        fp[category]["O"] = value
        return fp
    current_probe, timestamp = split_tcp_option(value)
    # set value in os_pattern
    if category not in fp:
        fp[category] = dict()
    fp[category]["O"] = current_probe
    #if timestamp:
        #fp[category]["tsval"] = timestamp[0]
        #fp[category]["tsver"] = timestamp[1]
    return fp


# Split OPS options among Probe 1-6.
def parse_tcp_options(fp, category, key_values):
    if "R=N" in key_values.split("%"):
        fp[category]["R"] = "N"
        if "P5" not in fp:
            fp["P5"] = dict()
        if "P6" not in fp:
            fp["P6"] = dict()
        fp["P5"]["R"] = "N"
        fp["P6"]["R"] = "N"
        return fp
    for key_value in key_values.split("%"):
        key, value = key_value.split("=")
        # get the number of the probe O1, O2
        fp[category][key] = value
        current = key[1]
        fp = parse_tcp_option(fp, "P" + str(current), value)
    return fp


# Parse categories with their right parsing methods.
def parse_category(fp, category, key_values):
    match category:
        case "SEQ":
            return parse_key_value_pairs(fp, category, key_values)
        case "OPS":
            return parse_tcp_options(fp, category, key_values)
        case "WIN":
            return parse_window_options(fp, category, key_values)
        case "ECN":
            return parse_key_value_pairs(fp, category, key_values)
        case "T1":
            return parse_key_value_pairs(fp, category, key_values)
        case "T2":
            return parse_key_value_pairs(fp, category, key_values)
        case "T3":
            return parse_key_value_pairs(fp, category, key_values)
        case "T4":
            return parse_key_value_pairs(fp, category, key_values)
        case "T5":
            return parse_key_value_pairs(fp, category, key_values)
        case "T6":
            return parse_key_value_pairs(fp, category, key_values)
        case "T7":
            return parse_key_value_pairs(fp, category, key_values)
        case "U1":
            return parse_key_value_pairs(fp, category, key_values)
        case "IE":
            return parse_key_value_pairs(fp, category, key_values)


# TS timestamp os_pattern = set_ip_timestamp(os_pattern, fp)
def parse_os_pattern(data):
    # OS Pattern Order
    # SEQ(SP, GCD, ISR, TI, II, SS, TS)
    # OPS(O1, O2, O3, O4, O5, O6)
    # WIN(W1, W2, W3, W4, W5, W6)
    # ECN(R, DF, T, TG, S, A, F, RD, Q)
    # T1(R, DF, T, TG, S, A, F, RD, Q)
    # T2(R)
    # T3(R, DF, T, TG, W, S, A, F, O, RD, Q)
    # T4(R, DF, T, TG, W, S, A, F, O, RD, Q)
    # T5(R, DF, T, TG, W, S, A, F, O, RD, Q)
    # T6(R, DF, T, TG, W, S, A, F, O, RD, Q)
    # T7(R, DF, T, TG, W, S, A, F, O, RD, Q)
    # U1(DF, T, TG, IPL, UN, RIPL, RID, RIPCK, RUCK, RUD)
    # IE(DFI, T, TG, CD)
    os_pattern = OSPatternTemplate()

    fp = dict()
    fp.clear()

    for line in data:
        line = line.strip()
        category, key_values = line.split("(", 1)
        if category not in fp:
            fp[category] = dict()
        fp = parse_category(fp, category, key_values[:-1])

    # Awful null-safety, I suppose...
    if "SEQ" in fp:
        os_pattern.seq_options = SEQOptions(fp["SEQ"])
        os_pattern.timestamp_hz = os_pattern.seq_options.TS_COUNT
    if "OPS" in fp:
        os_pattern.ops_options = OPSOptions(fp["OPS"])
    if "WIN" in fp:
        os_pattern.win_options = WINOptions(fp["WIN"])
    if "ECN" in fp:
        os_pattern.ecn_options = ECNOptions(fp["ECN"])
    if "P1" in fp:
        os_pattern.p1_options = TCPOptions(fp["P1"])
        #os_pattern.p1_options.A = "S"
    # Nmap tries to match probe responses by comparing the received ack with the sent seq. number,
    # so we *must* echo it correctly. This concerns P2-P6. P1 is somehow special and gets its own A option.
    if "P2" in fp:
        os_pattern.p2_options = TCPOptions(fp["P2"])
        os_pattern.p2_options.A = "S"
    if "P3" in fp:
        os_pattern.p3_options = TCPOptions(fp["P3"])
        os_pattern.p3_options.A = "S"
    if "P4" in fp:
        os_pattern.p4_options = TCPOptions(fp["P4"])
        os_pattern.p4_options.A = "S"
    if "P5" in fp:
        os_pattern.p5_options = TCPOptions(fp["P5"])
        os_pattern.p5_options.A = "S"
    if "P6" in fp:
        os_pattern.p6_options = TCPOptions(fp["P6"])
        os_pattern.p6_options.A = "S"
    if "T1" in fp:
        os_pattern.t1_options = TCPOptions(fp["T1"])
    if "T2" in fp:
        os_pattern.t2_options = TCPOptions(fp["T2"])
    if "T3" in fp:
        os_pattern.t3_options = TCPOptions(fp["T3"])
    if "T4" in fp:
        os_pattern.t4_options = TCPOptions(fp["T4"])
    if "T5" in fp:
        os_pattern.t5_options = TCPOptions(fp["T5"])
    if "T6" in fp:
        os_pattern.t6_options = TCPOptions(fp["T6"])
    if "T7" in fp:
        os_pattern.t7_options = TCPOptions(fp["T7"])
    if "U1" in fp:
        os_pattern.u1_options = UDPOptions(fp["U1"])
    if "IE" in fp:
        os_pattern.ie_options = IEOptions(fp["IE"])

    return os_pattern


# Parse a fingerprint from raw Nmap CLI Output after a scan.
def parse_detected_fingerprint(nmap_output):
    scan_lines = re.findall('OS:.*$', nmap_output, re.MULTILINE)
    for line in scan_lines:
        scan_lines[scan_lines.index(line)] = line.split("OS:")[1]
    scan_lines = ''.join(scan_lines)
    split_lines = scan_lines.replace(')', ')@').split('@')
    return split_lines[1:len(split_lines) - 1]


if __name__ == "__main__":
    sleep(1)
    with open("/".join(inspect.getabsfile(inspect.currentframe()).split("/")[0:6])
              + "/template/os_templates/" + template_list.template_list[template_list.use_template], "r") as fh:
        data = fh.readlines()
    parse_os_pattern(data)
    print(parse_os_pattern(data).to_string())
    print("==========================================================")
    (stdout, stderr) = Process.call("nmap -O -vv 127.0.0.1")
    print(stdout)
    detected_fingerprint = parse_detected_fingerprint(stdout)
    print(parse_os_pattern(detected_fingerprint).to_string())
    print("==========================================================")
    differences = parse_os_pattern(data).compare(parse_os_pattern(detected_fingerprint))
    for difference in differences:
        print(difference)
    os_details = re.findall('OS details:.*$', stdout, re.MULTILINE)
    if len(os_details) > 0:
        print(os_details)
