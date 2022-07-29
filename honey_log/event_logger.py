import json
import json
import re
import threading

import httpx
import requests

from honey_log.honeypot_event import HoneypotEvent, HoneypotEventDetails, HoneyPotNMapScanEventContent, \
    HoneypotEventEncoder, fix_up_json_string
from honey_os.process import Process
from honey_os.session import Session

url = "https://seclab.fiw.fhws.de/input/"
headers = {
    'Content-Type': 'application/json',
}


class EventLogger:
    def __init__(self, logger):
        self.event_id = 0
        self.output_buffer = []
        self.events_sent = 0
        self.rate_limit = 100
        self.log = logger
        self.session = Session()
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
                os_details = "Unknown"
            if len(device_type) > 0:
                os_details = ' '.join(device_type).join(os_details)
        else:
            os_details = os_details[0][12:]
        try:

            # URL to send the request to
            geolocation_url = 'https://geolocation-db.com/jsonp/' + ip_to_ping
            # Send request and decode the result
            with httpx.Client() as client:
                response = client.get(geolocation_url)
            result = response.content.decode()
            # Clean the returned string so it just contains the dictionary data for the IP address
            result = result.split("(")[1].strip(")")
            # Convert this data into a dictionary
            result = json.loads(result)

            country = result['country_name']
            city = result['city']

            if country is None:
                country = ""
            if city is None:
                city = ""
            event = json.dumps(
                HoneypotEvent(HoneypotEventDetails("scan", HoneyPotNMapScanEventContent(ip_to_ping, ', '.join([os_details, country, city])))),
                cls=HoneypotEventEncoder, indent=0).replace('\\"', '"').replace('\\n', '\n').replace('}\"', '}').replace(
                '\"{', '{')
            self.output_buffer.append(fix_up_json_string(event))
        except Exception as e:
            import traceback
            traceback.print_exc()


    def async_report_event(self, event, srcIP):
        self.log.debug("Appending event to event logger output buffer: {}".format(event))
        if not self.session.in_session(srcIP, False, self.log):
            print("IP not in session, running an Nmap scan on them...")
            self.internal_ping_back_and_report(srcIP)
        print("Async reporting event.", event)
        self.output_buffer.append(fix_up_json_string(event))

    def process_output_buffer(self):
        with httpx.Client(headers=headers) as client:
            for output in self.output_buffer:
                if self.events_sent < self.rate_limit:
                    client.post(url, data=output)
                    self.output_buffer.remove(output)
                    self.events_sent = self.events_sent + 1
        self.events_sent = self.events_sent - 5
        if self.events_sent < 0:
            self.events_sent = 0
        threading.Timer(5, self.process_output_buffer).start()



