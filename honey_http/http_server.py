import hashlib
from datetime import datetime
from flask import Flask, render_template, request
from werkzeug.utils import secure_filename
from honey_log.client.logging_client import LoggingClient
from honey_log.honeypot_event import HoneyPotHTTPEventContent, HoneyPotLoginEventContent, HoneyPotFileEventContent

logging_client = LoggingClient("HTTP")
app = Flask(__name__)


@app.route("/", methods=['GET'])
def start():
    logging_client.report_event("http",
                                HoneyPotHTTPEventContent(request.remote_addr, request.method, request.path,
                                                         request.headers.get('User-Agent')))
    return render_template("iisstart.html")


@app.route("/index/", methods=['GET'])
def index():
    logging_client.report_event("http",
                                HoneyPotHTTPEventContent(request.remote_addr, request.method, request.path,
                                                         request.headers.get('User-Agent')))
    return render_template("iisstart.html")


@app.route("/index.html/", methods=['GET'])
def index_html():
    logging_client.report_event("http",
                                HoneyPotHTTPEventContent(request.remote_addr, request.method, request.path,
                                                         request.headers.get('User-Agent')))
    return render_template("iisstart.html")


@app.route("/iisstart.html/", methods=['GET'])
def iisstart():
    logging_client.report_event("http",
                                HoneyPotHTTPEventContent(request.remote_addr, request.method, request.path,
                                                         request.headers.get('User-Agent')))
    return render_template("iisstart.html")


@app.route('/login.html/', methods=['GET', 'POST'])
def login_html():
    logging_client.report_event("http",
                                HoneyPotHTTPEventContent(request.remote_addr, request.method, request.path,
                                                         request.headers.get('User-Agent')))
    error = None
    if request.method == 'POST':
        logging_client.report_event("login",
                                    HoneyPotLoginEventContent(request.remote_addr, "HTTP", request.form['username'],
                                                              request.form['password']))
        error = 'Invalid Credentials. Please try again.'
    return render_template('login.html', error=error)


@app.route('/login/', methods=['GET', 'POST'])
def login():
    logging_client.report_event("http",
                                HoneyPotHTTPEventContent(request.remote_addr, request.method, request.path,
                                                         request.headers.get('User-Agent')))
    error = None
    if request.method == 'POST':
        logging_client.report_event("login",
                                    HoneyPotLoginEventContent(request.remote_addr, "HTTP", request.form['username'],
                                                              request.form['password']))
        error = 'Invalid Credentials. Please try again.'
    return render_template('login.html', error=error)


@app.route('/upload.html/', methods=['GET', 'POST'])
def upload_file_html():
    logging_client.report_event("http",
                                HoneyPotHTTPEventContent(request.remote_addr, request.method, request.path,
                                                         request.headers.get('User-Agent')))
    if request.method == 'POST':
        # check if the post request has the file part
        if 'file' not in request.files:
            return render_template('upload.html')
        file = request.files['file']
        if file:
            filename = secure_filename(file.filename)
            joined_name = "/tmp/malware/" + '/'.join(filename.split('/')[:-1]) + "/" + datetime.now().strftime("%d-%m-%Y-%H-%M-%S-%f") + "@" + filename.split('/')[-1] + "@" + request.remote_addr
            file.save(joined_name)
            with open(joined_name).read() as downloaded_file:
                file_sha1 = hashlib.sha1(downloaded_file)
                file_md5 = hashlib.md5(downloaded_file)
                file_sha256 = hashlib.sha256(downloaded_file)
                logging_client.report_event("file",
                                            HoneyPotFileEventContent(request.remote_addr, "HTTP", filename,
                                                                     file_md5.hexdigest(), file_sha1.hexdigest(),
                                                                     file_sha256.hexdigest(), len(downloaded_file)))

            return render_template('iisstart.html')
    return render_template('upload.html')


@app.route('/upload/', methods=['GET', 'POST'])
def upload_file():
    logging_client.report_event("http",
                                HoneyPotHTTPEventContent(request.remote_addr, request.method, request.path,
                                                         request.headers.get('User-Agent')))
    if request.method == 'POST':
        # check if the post request has the file part
        if 'file' not in request.files:
            return render_template('upload.html')
        file = request.files['file']
        if file:
            filename = secure_filename(file.filename)
            joined_name = "/tmp/malware/" + '/'.join(filename.split('/')[:-1]) + "/" + datetime.now().strftime(
                "%d-%m-%Y-%H-%M-%S-%f") + "@" + filename.split('/')[-1] + "@" + request.remote_addr
            file.save(joined_name)
            with open(joined_name).read() as downloaded_file:
                file_sha1 = hashlib.sha1(downloaded_file)
                file_md5 = hashlib.md5(downloaded_file)
                file_sha256 = hashlib.sha256(downloaded_file)
                logging_client.report_event("file",
                                            HoneyPotFileEventContent(request.remote_addr, "HTTP", filename,
                                                                     file_md5.hexdigest(), file_sha1.hexdigest(),
                                                                     file_sha256.hexdigest(), len(downloaded_file)))

            return render_template('iisstart.html')
    return render_template('upload.html')


@app.route('/upload.php/', methods=['GET', 'POST'])
def upload_file_php():
    logging_client.report_event("http",
                                HoneyPotHTTPEventContent(request.remote_addr, request.method, request.path,
                                                         request.headers.get('User-Agent')))
    if request.method == 'POST':
        # check if the post request has the file part
        if 'file' not in request.files:
            return render_template('upload.html')
        file = request.files['file']
        if file:
            filename = secure_filename(file.filename)
            joined_name = "/tmp/malware/" + '/'.join(filename.split('/')[:-1]) + "/" + datetime.now().strftime(
                "%d-%m-%Y-%H-%M-%S-%f") + "@" + filename.split('/')[-1] + "@" + request.remote_addr
            file.save(joined_name)
            with open(joined_name).read() as downloaded_file:
                file_sha1 = hashlib.sha1(downloaded_file)
                file_md5 = hashlib.md5(downloaded_file)
                file_sha256 = hashlib.sha256(downloaded_file)
                logging_client.report_event("file",
                                            HoneyPotFileEventContent(request.remote_addr, "HTTP", filename,
                                                                     file_md5.hexdigest(), file_sha1.hexdigest(),
                                                                     file_sha256.hexdigest(), len(downloaded_file)))

            return render_template('iisstart.html')
    return render_template('upload.html')


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=8080, debug=True)
