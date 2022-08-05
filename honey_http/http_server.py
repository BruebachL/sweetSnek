from flask import Flask, render_template, request
import subprocess

from honey_log.client.logging_client import LoggingClient
from honey_log.honeypot_event import HoneyPotHTTPEventContent

logging_client = LoggingClient("HTTP")
app = Flask(__name__)


@app.route("/index", methods=['GET'])
def index():
    logging_client.report_event("http",
                                HoneyPotHTTPEventContent(request.remote_addr, request.method, request.path,
                                                         request.headers.get('User-Agent')))
    return render_template("iisstart.htm")


@app.route("/index.html", methods=['GET'])
def index_html():
    logging_client.report_event("http",
                                HoneyPotHTTPEventContent(request.remote_addr, request.method, request.path,
                                                         request.headers.get('User-Agent')))
    return render_template("iisstart.htm")


@app.route("/iisstart.html", methods=['GET'])
def iisstart():
    logging_client.report_event("http",
                                HoneyPotHTTPEventContent(request.remote_addr, request.method, request.path,
                                                         request.headers.get('User-Agent')))
    return render_template("iisstart.htm")


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=8080, debug=True)
