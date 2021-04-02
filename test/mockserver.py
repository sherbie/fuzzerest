import flask
import logging
from flask import Flask, abort, request
import time


app = Flask(__name__)


@app.route("/json", methods=["GET"])
def get_json():
    res = flask.Response('{"success": true, "num": 1}\n')
    res.status_code = 200
    res.headers["Content-type"] = "application/json"


@app.route("/multiple", methods=["GET", "POST"])
def get_post_multiple():
    res = flask.Response('{"success": true, "num": 2}\n')
    res.status_code = 200
    res.headers["Content-type"] = "application/json"
    return res


@app.route("/any/method", methods=["GET", "POST", "HEAD", "PUT", "DELETE"])
def any_method():
    res = flask.Response('{"success": true, "num": 3}\n')
    res.status_code = 200
    res.headers["Content-type"] = "application/json"
    return res


@app.route("/watch", methods=["GET"])
def get_watch():
    res = flask.Response('{"success": false, "reason": "Video not found"}\n')
    res.status_code = 200
    res.headers["Content-type"] = "application/json"
    return res


@app.route("/sleepabit", methods=["GET"])
def get_sleepabit():
    time.sleep(1)
    res = flask.Response('{"success": true, "num": 3}\n')
    res.status_code = 200
    res.headers["Content-type"] = "application/json"
    return res


@app.route("/delayabit", methods=["GET"])
def get_delayabit():
    res = flask.Response('{"success": true, "num": 4}\n')
    res.status_code = 200
    res.headers["Content-type"] = "application/json"
    return res


@app.route("/fail", methods=["GET"])
def get_fail():
    return abort(500)


@app.route("/die", methods=["GET"])
def get_die():
    func = request.environ.get("werkzeug.server.shutdown")
    if func is None:
        raise RuntimeError("Not running with the Werkzeug Server")
    func()


def run_mock_server():
    print("Starting mock server at 127.0.0.1:8080")
    app.logger.setLevel(logging.INFO)
    app.run(host="0.0.0.0", port=8080)


if __name__ == "__main__":
    run_mock_server()
