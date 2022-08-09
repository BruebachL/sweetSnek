from flask import Flask, render_template, request
import subprocess

from honey_log.client.logging_client import LoggingClient
from honey_log.honeypot_event import HoneyPotHTTPEventContent, HoneyPotLoginEventContent

logging_client = LoggingClient("HTTP")
app = Flask(__name__)


@app.route("/", methods=['GET'])
def start():
    logging_client.report_event("http",
                                HoneyPotHTTPEventContent(request.remote_addr, request.method, request.path,
                                                         request.headers.get('User-Agent')))
    return render_template("iisstart.html")

@app.route("/index", methods=['GET'])
def index():
    logging_client.report_event("http",
                                HoneyPotHTTPEventContent(request.remote_addr, request.method, request.path,
                                                         request.headers.get('User-Agent')))
    return render_template("iisstart.html")


@app.route("/index.html", methods=['GET'])
def index_html():
    logging_client.report_event("http",
                                HoneyPotHTTPEventContent(request.remote_addr, request.method, request.path,
                                                         request.headers.get('User-Agent')))
    return render_template("iisstart.html")


@app.route("/iisstart.html", methods=['GET'])
def iisstart():
    logging_client.report_event("http",
                                HoneyPotHTTPEventContent(request.remote_addr, request.method, request.path,
                                                         request.headers.get('User-Agent')))
    return render_template("iisstart.html")


@app.route('/login.html', methods=['GET', 'POST'])
def login_html():
    error = None
    if request.method == 'POST':
        logging_client.report_event("login", HoneyPotLoginEventContent(request.remote_addr, "HTTP", request.form['username'], request.form['password']))
        error = 'Invalid Credentials. Please try again.'
    return render_template('login.html', error=error)


@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        logging_client.report_event("login", HoneyPotLoginEventContent(request.remote_addr, "HTTP", request.form['username'], request.form['password']))
        error = 'Invalid Credentials. Please try again.'
    return render_template('login.html', error=error)


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=8080, debug=True)
