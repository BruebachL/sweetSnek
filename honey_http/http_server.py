from flask import Flask, render_template, request
import subprocess

from honey_log.client.logging_client import LoggingClient
from honey_log.honeypot_event import HoneyPotHTTPEventContent

logging_client = LoggingClient("HTTP")
app = Flask(__name__)

@app.route("/index", methods=['GET'])
def test_index():
    print(request.headers)
    logging_client.report_event("http", HoneyPotHTTPEventContent(request.headers.get('Host'), request.method, request.path, request.headers.get('User-Agent')))
    return render_template("iisstart.htm")

@app.route("/robots", methods=['POST'])
def pull_from_git():
    p = subprocess.Popen('sudo /etc/init.d/logging-server stop', shell=True)
    p.wait()

    p = subprocess.Popen(['git', 'pull'], cwd='/root/sweetSnek/')
    # out,err = p.communicate()
    p.wait()

    p = subprocess.Popen('sudo /etc/init.d/logging-server start', shell=True)
    p.wait()

    return "Done!"


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=8080, debug=True)
