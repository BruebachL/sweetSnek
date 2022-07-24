from flask import Flask
import subprocess

app = Flask(__name__)


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
