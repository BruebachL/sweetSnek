import asyncio
import json
import re
import threading

import aiohttp
import requests

from honeypot_event import HoneypotEvent, HoneypotEventDetails, HoneyPotNMapScanEventContent, HoneypotEventEncoder
from osfingerprinting.process import Process

url = "https://seclab.fiw.fhws.de/input/"
headers = {
    'Content-Type': 'application/json',
}


class EventLogger:
    def __init__(self):
        self.event_id = 0

    def ping_back_and_report(self, ip_to_ping):
        threading.Thread(target=self.internal_ping_back_and_report, args=(ip_to_ping,)).start()

    def internal_ping_back_and_report(self, ip_to_ping):
        cmd = "nmap -O -vv --top-ports 50 " + ip_to_ping
        print("Initiating Nmap counter-scan: ", cmd)
        (stdout, stderr) = Process.call(cmd)
        os_details = re.findall('OS details:.*$', stdout, re.MULTILINE)[0].split(':')[1]
        device_type = re.findall('Device type:.*$', stdout, re.MULTILINE)[0].split(':')[1]
        running_guess = re.findall('Running (JUST GUESSING):.*$', stdout, re.MULTILINE)[0].split(':')[1]
        os_cpe = re.findall('OS CPE:.*$', stdout, re.MULTILINE)[0].split(':')[1]
        aggressive_os_guesses = re.findall('Aggressive OS guesses:.*$', stdout, re.MULTILINE)[0].split(':')[1]
        print(device_type)
        print(running_guess)
        print(os_cpe)
        print(aggressive_os_guesses)

        if len(os_details) <= 0 or os_details[0] == "" or os_details[0] is None or os_details is None:
            os_details = "Unknown."
        else:
            os_details = os_details[0][12:]
        event = json.dumps(
            HoneypotEvent(HoneypotEventDetails("scan", HoneyPotNMapScanEventContent(ip_to_ping, os_details))),
            cls=HoneypotEventEncoder, indent=0).replace('\\"', '"').replace('\\n', '\n').replace('}\"', '}').replace(
            '\"{', '{')

        self.do_post(event)

    def async_report_event(self, event):
        threading.Thread(target=self.do_post, args=(event,)).start()

    def do_post(self, event):
        resp = requests.post(url, headers=headers, data=event)
        print("-> Sent event type %s and got server response %s" % (event.split(',')[3].split(':')[1], resp))

