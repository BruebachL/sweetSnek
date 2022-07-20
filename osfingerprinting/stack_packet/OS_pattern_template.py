import math
import random
import time
from datetime import datetime, timedelta


def get_elapsed_time_in_microseconds(timer):
    now = datetime.now()
    diff = timer - now
    return diff / -timedelta(microseconds=1)


def get_elapsed_ticks(timer, timestamp_hz):
    if timestamp_hz != 0:
        return get_elapsed_time_in_microseconds(timer) / (1000000 / timestamp_hz)
    else:
        return get_elapsed_time_in_microseconds(timer)


class OSPatternTemplate(object):
    """
    Defining the OS characteristics
    Take the values from the Nmap fingerprint
    """

    def __init__(self):
        self.seq_options = None
        self.ops_options = None
        self.win_options = None
        self.ecn_options = None
        self.p1_options = None
        self.p2_options = None
        self.p3_options = None
        self.p4_options = None
        self.p5_options = None
        self.p6_options = None
        self.t1_options = None
        self.t2_options = None
        self.t3_options = None
        self.t4_options = None
        self.t5_options = None
        self.t6_options = None
        self.t7_options = None
        self.tcp_options = [self.t1_options, self.t2_options, self.t3_options, self.t4_options, self.t5_options,
                            self.t6_options, self.t7_options]
        self.u1_options = None
        self.ie_options = None

        self.received_ttls = []

        # start value of SEQNR
        self.TCP_SEQ_NR_tmp = 0
        self.initial_ISN = 0
        self.generated_ISNS = []
        self.generated_ISNS_2 = []
        self.generated_ISNS_3 = []
        self.generated_TIMESTAMPS = []
        self.tv_ISN = 0

        # TI - CI - II
        # difference of IP header ID fields by different response groups
        #  I (incremental)
        #  RI (random positive increments)
        #  BI (broken increment)
        self.IP_ID_CI_CNT = 'I'  # T5-7 - CI field
        self.IP_ID_II_CNT = 'I'  # IE - II field
        self.IP_ID_tmp = 1

        # Timestamp in reply packets
        self.TCP_Timestamp_tmp = 1
        # Timestamp counter 1... if TS = U
        self.TCP_TS_CNT = 1

        # U1 probe (UDP)
        # Clear data from UDP reply
        self.CL_UDP_DATA = 1
        # Set normally unused, second 4 bytes of ICMP header
        self.UN = 0

        # IE probe
        # 0 =^ Z
        # S =^ same as from probes
        self.ICMP_CODE = 'S'

        self.timer = datetime.now()
        self.isn = 0

        self.time_div = 0.1

        self.boot_time = time.monotonic()
        self.boot_time_timestamp = time.time()
        self.seqcalls = 0
        self.timestamp = 0
        self.timestamp_hz = -1
        self.tv = None
        self.tv_real = None
        self.tv_periodic = None
        self.drift = 1.0 + (random.randint(0, pow(2, 16)) % 140 - 70) / 100000.0

    def timer_sub(self, timestamp_one, timestamp_two):
        return timestamp_one - timestamp_two

    def timer_add(self, timestamp_one, timestamp_two):
        return timestamp_one + timestamp_two

    def elapsed_seconds_since_boot(self):
        return time.monotonic() - self.boot_time

    def get_fictional_isn_timer(self):
        return self.elapsed_seconds_since_boot() * int(self.seq_options.TS_COUNT / 100)

    def generate_isn_diffs(self):
        diffs = []
        for i in range(len(self.generated_ISNS) - 2):
            diffs.append(self.generated_ISNS[i + 1] - self.generated_ISNS[i])
        return diffs

    def time_correct(self, ticks, diff):
        diff.replace(second=0)
        diff.replace(microsecond=int(diff.microsecond % ticks))
        diff_time = self.timer_sub(self.tv, diff)
        self.tv.replace(second=self.tv.second - diff_time.seconds, microsecond=self.tv.microsecond - diff_time.microseconds)

    def personality_time(self):
        diff = self.timer_sub(self.tv_periodic, self.tv_real)
        self.tv_real = self.tv_periodic
        ms = diff.seconds * 10000 + (diff.microseconds / 100)
        ms *= self.drift
        self.tv.replace(second=self.tv.second + int(ms / 10000), microsecond=int((ms % 10000) * 100))
        return self.tv

    def tcp_personality_time(self):
        self.tv_periodic = datetime.now()
        diff = self.personality_time()
        if self.timestamp_hz:
            timestamp_hz = self.timestamp_hz
            if timestamp_hz == -1:
                timestamp_hz = 2
            ticks = 1000000 / timestamp_hz
            if not ticks:
                slow_hz = diff.second * timestamp_hz + diff.microsecond
            else:
                slow_hz = diff.second * timestamp_hz + diff.microsecond / ticks
                self.time_correct(ticks, diff)
            self.timestamp += slow_hz
        else:
            slow_hz = 0
            self.timestamp = 0

        return slow_hz

    def tcp_personality_seq(self):
        self.seqcalls += 1
        if self.tv is None:
            self.tv_periodic = datetime.now()
            self.tv_real = self.tv = self.tv_periodic
            if self.timestamp_hz != 0:
                self.drift = 1.0 + (random.randint(0, pow(2, 16)) % self.timestamp_hz) / 100000.0
            else:
                self.drift = 1.0 + (random.randint(0, pow(2, 16)) % 1) / 100000.0

            if self.timestamp == 0:
                self.timestamp = random.randrange(pow(2, 32)) % 1728000  # rand_uint32(honeyd_rand)
        return self.tcp_personality_time()

    # / *Now we look at TCP Timestamp sequence prediction
    # Battle plan:
    # 1) Compute average increments per second, and variance in incr.per second
    # 2) If any are 0, set to constant
    # 3) If variance is high, set to random incr.[skip for now ]
    # 4) if ~10 / second, set to appropriate thing
    # 5) Same with ~100 / sec

    def tcp_timestamp_sequence_prediction(self, timestamps):
        uptime = 0
        avg_ts_hz = 0
        for i in range(len(timestamps) - 1):
            dhz = timestamps[i] / (100066 / 100000)
            avg_ts_hz += dhz / (len(timestamps) - 1)
        return avg_ts_hz

    # dhz = (double) ts_diffs[i] / (time_usec_diffs[i] / 1000000.0);
    # / * printf("ts incremented by %d in %li usec -- %fHZ\n", ts_diffs[i], time_usec_diffs[i], dhz); * /
    # avg_ts_hz += dhz / (hss->si.responses - 1);
    # }
    #
    # if (avg_ts_hz > 0 & & avg_ts_hz < 5.66) {/ * relatively wide range because sampling time so short and frequency so slow * /
    # hss->si.ts_seqclass = TS_SEQ_2HZ;
    # uptime = hss->si.timestamps[0] / 2;
    # }
    # else if (avg_ts_hz > 70 & & avg_ts_hz < 150) {
    # hss->si.ts_seqclass = TS_SEQ_100HZ;
    # uptime = hss->si.timestamps[0] / 100;
    # }
    # else if (avg_ts_hz > 724 & & avg_ts_hz < 1448) {
    # hss->si.ts_seqclass = TS_SEQ_1000HZ;
    # uptime = hss->si.timestamps[0] / 1000;
    # }
    # else if (avg_ts_hz > 0) {
    # hss->si.ts_seqclass = TS_SEQ_OTHER_NUM;
    # uptime = hss->si.timestamps[0] / (unsigned int)(0.5 + avg_ts_hz);
    # }
    #
    # if (uptime > 63072000) {
    # / * Up 2 years?  Perhaps, but they're probably lying. */
    # if (o.debugging) {
    # / * long long is probably excessive for number of days, but sick of
    # * truncation warnings and finding the right format string for time_t
    # * /
    # log_write(LOG_STDOUT, "Ignoring claimed %s uptime of %lld days\n",
    # hss->target->targetipstr(), (long long) (uptime / 86400));
    # }
    # uptime = 0;
    # }

    def get_ttl_padding(self):
        max_value = self.get_highest_ttl_padding()
        min_value = self.get_lowest_ttl_padding()
        if max_value < min_value:
            return max_value
        if min_value > max_value:
            return min_value
        if min_value < 0 and max_value < -min_value:
            return max_value
        return min(max_value, -min_value)

    def get_lowest_ttl_padding(self):
        return 37 - min(self.received_ttls)

    def get_highest_ttl_padding(self):
        return 60 - max(self.received_ttls)

    @property
    def ISR_mean(self):
        # return (int(self.ISR_MIN,16) + int(self.ISR_MAX,16)) / 2
        return (self.seq_options.ISR_MIN + self.seq_options.ISR_MAX) / 2

    @property
    def SEQNr_mean(self):
        if self.seq_options.GCD > 9:
            return int(self.seq_options.GCD)
        else:
            return math.trunc(round((2 ** (self.ISR_mean / 8)) * self.time_div))

    @property
    def SP_mean(self):
        return (self.seq_options.SP_MIN + self.seq_options.SP_MAX) / 2

    @property
    def SEQ_std_dev(self):
        return math.trunc(round((2 ** (self.SP_mean / 8))))

    @property
    def SEQ_MIN(self):
        _SEQ_MIN = math.trunc(round((2 ** (self.seq_options.ISR_MIN / 8)) * self.time_div))
        _SEQ_MIN -= (self.SEQ_std_dev / 8)
        return _SEQ_MIN

    @property
    def SEQ_MAX(self):
        _SEQ_MAX = math.trunc(round((2 ** (self.seq_options.ISR_MAX / 8)) * self.time_div))
        _SEQ_MAX += (self.SEQ_std_dev / 8)
        return _SEQ_MAX

    def compare(self, other_fingerprint):
        discrepancies = []
        if self.seq_options is not None and other_fingerprint.seq_options is not None:
            if not len(self.seq_options.compare(other_fingerprint.seq_options)["SEQ"]) == 0:
                discrepancies.append(self.seq_options.compare(other_fingerprint.seq_options))
        if self.ops_options is not None and other_fingerprint.ops_options is not None:
            if not len(self.ops_options.compare(other_fingerprint.ops_options)["OPS"]) == 0:
                discrepancies.append(self.ops_options.compare(other_fingerprint.ops_options))
        if self.win_options is not None and other_fingerprint.win_options is not None:
            if not len(self.win_options.compare(other_fingerprint.win_options)["WIN"]) == 0:
                discrepancies.append(self.win_options.compare(other_fingerprint.win_options))
        if not len(self.ecn_options.compare(other_fingerprint.ecn_options)["ECN"]) == 0:
            discrepancies.append(self.ecn_options.compare(other_fingerprint.ecn_options))
        if not len(self.t1_options.compare(other_fingerprint.t1_options)["TCP"]) == 0:
            discrepancies.append(self.t1_options.compare(other_fingerprint.t1_options))
        if not len(self.t2_options.compare(other_fingerprint.t2_options)["TCP"]) == 0:
            discrepancies.append(self.t2_options.compare(other_fingerprint.t2_options))
        if not len(self.t3_options.compare(other_fingerprint.t3_options)["TCP"]) == 0:
            discrepancies.append(self.t3_options.compare(other_fingerprint.t3_options))
        if not len(self.t4_options.compare(other_fingerprint.t4_options)["TCP"]) == 0:
            discrepancies.append(self.t4_options.compare(other_fingerprint.t4_options))
        if not len(self.t5_options.compare(other_fingerprint.t5_options)["TCP"]) == 0:
            discrepancies.append(self.t5_options.compare(other_fingerprint.t5_options))
        if not len(self.t6_options.compare(other_fingerprint.t6_options)["TCP"]) == 0:
            discrepancies.append(self.t6_options.compare(other_fingerprint.t6_options))
        if not len(self.t7_options.compare(other_fingerprint.t7_options)["TCP"]) == 0:
            discrepancies.append(self.t7_options.compare(other_fingerprint.t7_options))
        if not len(self.u1_options.compare(other_fingerprint.u1_options)["UDP"]) == 0:
            discrepancies.append(self.u1_options.compare(other_fingerprint.u1_options))
        if not len(self.ie_options.compare(other_fingerprint.ie_options)["IE"]) == 0:
            discrepancies.append(self.ie_options.compare(other_fingerprint.ie_options))
        return discrepancies

    def __str__(self):
        return '\t\t\t TCP_SEQ_NR_tmp: ' + str(self.TCP_SEQ_NR_tmp) + \
               '\t\t IP_ID_CI_CNT: ' + str(self.IP_ID_CI_CNT) + \
               '\t\t IP_ID_II_CNT: ' + str(self.IP_ID_II_CNT) + \
               '\t\t IP_ID_tmp: ' + str(self.IP_ID_tmp) + \
               '\n TCP_Timestamp_tmp: ' + str(self.TCP_Timestamp_tmp) + \
               '\t\t TCP_TS_CNT: ' + str(self.TCP_TS_CNT) + \
               '\n TCP_FLAGS: \t' + str(self.TCP_FLAGS) + \
               '\n TCP_OPTIONS: \t P1' + str(self.p1_options) + \
               '\t\t P2' + str(self.p2_options) + \
               '\t\t P3' + str(self.p3_options) + \
               '\n \t\t P4' + str(self.p4_options) + \
               '\t\t P5' + str(self.p5_options) + \
               '\t\t P6' + str(self.p6_options) + \
               '\n \t\t ECN' + str(self.ecn_options) + \
               '\t\t T2' + str(self.t2_options) + \
               '\t\t T3' + str(self.t3_options) + \
               '\n \t\t T4' + str(self.t4_options) + \
               '\t\t T5' + str(self.t5_options) + \
               '\t\t T6' + str(self.t6_options) + \
               '\n \t\t T7' + str(self.t7_options) + \
               '\t\t U1' + str(self.u1_options) + \
               '\t\t\t\t\t IE' + str(self.ie_options) + \
               '\n CL_UDP_DATA: ' + str(self.CL_UDP_DATA) + \
               '\t\t\t UN: ' + str(self.UN) + \
               '\t\t\t\t ICMP_CODE: ' + str(self.ICMP_CODE)

    def to_string(self):
        return self.seq_options.__str__() + "\n" + self.ops_options.__str__() + "\n" + self.win_options.__str__() \
               + "\n" + self.ecn_options.__str__() + "\n" + self.t1_options.__str__() + "\n" + self.t2_options.__str__() \
               + "\n" + self.t3_options.__str__() + "\n" + self.t4_options.__str__() + "\n" + self.t5_options.__str__() \
               + "\n" + self.t6_options.__str__() + "\n" + self.t7_options.__str__() + "\n" + self.u1_options.__str__() \
               + "\n" + self.ie_options.__str__()
