import threading

import httpx


class HttpOutput:

    def __init__(self):
        self.config = None
        self.output_buffer = []
        self.events_sent = 0
        self.rate_limit = 200
        self.process_output_buffer()

    def parse_url_from_config(self):
        parsed_urls = []
        for url in self.config.config['URL']:
            parsed_urls.append(url)
        return parsed_urls

    def parse_headers_from_config(self):
        parsed_headers = {}
        for header in self.config.config['Headers']:
            split_header = header.split(': ')
            parsed_headers[split_header[0].removeprefix("'").removesuffix("'")] = split_header[1].removeprefix("'").removesuffix("'")

    def process_output_buffer(self):
        if self.config is not None:
            with httpx.Client(headers=self.parse_headers_from_config()) as client:
                for output in self.output_buffer:
                    if self.events_sent < self.rate_limit:
                        for url in self.parse_url_from_config():
                            client.post(url, data=output)
                        self.output_buffer.remove(output)
                        self.events_sent = self.events_sent + 1
            self.events_sent = 0
        threading.Timer(1, self.process_output_buffer).start()


http_output = HttpOutput()


def handle(event, config):
    http_output.config = config
    http_output.output_buffer.append(event)


