import json
import json
import re
import threading

import requests

from event_logging.honeypot_event import HoneypotEvent, HoneypotEventDetails, HoneyPotNMapScanEventContent, \
    HoneypotEventEncoder
from osfingerprinting.process import Process

url = "https://seclab.fiw.fhws.de/input/"
headers = {
    'Content-Type': 'application/json',
}


class EventLogger:
    def __init__(self):
        self.event_id = 0
        self.output_buffer = []
        self.events_sent = 0
        self.rate_limit = 100
        self.process_output_buffer()

    def ping_back_and_report(self, ip_to_ping):
        threading.Thread(target=self.internal_ping_back_and_report, args=(ip_to_ping,)).start()

    def internal_ping_back_and_report(self, ip_to_ping):
        cmd = "nmap -O -vv --top-ports 50 " + ip_to_ping
        print("Initiating Nmap counter-scan: ", cmd)
        (stdout, stderr) = Process.call(cmd)
        os_details = re.findall('OS details:.*$', stdout, re.MULTILINE)
        if len(os_details) > 0:
            print(os_details)
            os_details = os_details[0].split(':')[1]
        device_type = re.findall('Device type:.*$', stdout, re.MULTILINE)
        if len(device_type) > 0:
            device_type = device_type[0].split(':')[1].split('|')[0]
        running_guess = re.findall('Running (JUST GUESSING):.*$', stdout, re.MULTILINE)
        if len(running_guess) > 0:
            running_guess = running_guess[0].split(':')[1].split(',')[0]
        aggressive_os_guesses = re.findall('Aggressive OS guesses:.*$', stdout, re.MULTILINE)
        if len(aggressive_os_guesses) > 0:
            aggressive_os_guesses = aggressive_os_guesses[0].split(':')[1].split(',')[0]
        if len(os_details) <= 0 or os_details[0] == "" or os_details[0] is None or os_details is None:
            if len(running_guess) > 0:
                os_details = running_guess
            elif len(aggressive_os_guesses) > 0:
                os_details = aggressive_os_guesses
            else:
                os_details = "Unknown."
            if len(device_type) > 0:
                os_details = ' '.join(device_type).join(os_details)
        else:
            os_details = os_details[0][12:]

        event = json.dumps(
            HoneypotEvent(HoneypotEventDetails("scan", HoneyPotNMapScanEventContent(ip_to_ping, os_details))),
            cls=HoneypotEventEncoder, indent=0).replace('\\"', '"').replace('\\n', '\n').replace('}\"', '}').replace(
            '\"{', '{')

        self.do_post(event)

    def async_report_event(self, event):
        self.output_buffer.append(event)

    def process_output_buffer(self):
        for output in self.output_buffer:
            if self.events_sent < self.rate_limit:
                threading.Thread(target=self.do_post, args=(output,)).start()
                self.output_buffer.remove(output)
                self.events_sent = self.events_sent + 1
        self.events_sent = self.events_sent - 5
        if self.events_sent < 0:
            self.events_sent = 0
        threading.Timer(5, self.process_output_buffer).start()



    def do_post(self, event):
        resp = requests.post(url, headers=headers, data=event)
        print("-> Sent event type %s and got server response %s" % (event.split(',')[3].split(':')[1], resp))

