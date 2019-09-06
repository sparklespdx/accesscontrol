import os
from flask import Flask, redirect, url_for, render_template, jsonify, request
# from flask_dance.contrib.google import make_google_blueprint, google
from access import *

import oauthlib


readers = initialize(config, logger)
app = Flask(__name__)


# app.secret_key = os.environ.get("FLASK_SECRET_KEY", "supersekrit")
# app.config["GOOGLE_OAUTH_CLIENT_ID"] = os.environ.get("GOOGLE_OAUTH_CLIENT_ID")
# app.config["GOOGLE_OAUTH_CLIENT_SECRET"] = os.environ.get("GOOGLE_OAUTH_CLIENT_SECRET")
# google_bp = make_google_blueprint(scope=["https://www.googleapis.com/auth/userinfo.profile", "openid", "https://www.googleapis.com/auth/userinfo.email"])
# app.register_blueprint(google_bp, url_prefix="/login")

webapp_user_config_name = "BEEF0"


@app.route("/doors")
def doors():
#    if not google.authorized:
#        return redirect(url_for("google.login"))

    doors = []
    for r in readers:
        doors.append({
            "name": r.door.name,
            "last_opened": r.door.last_opened,
            "unlocked": r.door.unlocked,
            "activated": r.door.latch.activated
        })
    return jsonify({'doors': doors})

@app.route("/doors/<door_name>/open", methods=['POST'])
def door_opener(door_name):
#    if not google.authorized:
#        return redirect(url_for("google.login"))

    for r in readers:
        if r.door.name == door_name:
            r.door.open_door(config.users.get(webapp_user_config_name))
            return jsonify({"message": "yay door is open"}), 200
    return jsonify({"message": "couldn't find door with name {}".format(door_name)}), 404


@app.route("/doors/<door_name>/unlock", methods=['POST'])
def door_unlocker(door_name):
#    if not google.authorized:
#        return redirect(url_for("google.login"))

    for r in readers:
        if r.door.name == door_name and not r.door.unlocked:
            r.door.toggle_lock(config.users.get(webapp_user_config_name))
            return jsonify({"message": "yay door is unlocked"}), 200
        else:
            return jsonify({"message": "door was already unlocked"}), 418
    return jsonify({"message": "couldn't find door with name {}".format(door_name)}), 404


@app.route("/doors/<door_name>/lock", methods=['POST'])
def door_locker(door_name):
#    if not google.authorized:
#        return redirect(url_for("google.login"))

    for r in readers:
        if r.door.name == door_name and r.door.unlocked:
            r.door.toggle_lock(config.users.get(webapp_user_config_name))
            return jsonify({"message": "yay door is locked"}), 200
        else:
            return jsonify({"message": "door was already locked"}), 418
    return jsonify({"message": "couldn't find door with name {}".format(door_name)}), 404


@app.route("/")
def index():
#    if not google.authorized:
#        return redirect(url_for("google.login"))
    return app.send_static_file("index.html")


# @app.route("/user")
# def user():
#     if not google.authorized:
#         return redirect(url_for("google.login"))
#     try:
#         resp = google.get("/oauth2/v1/userinfo")
#         assert resp.ok, resp.text
#     except oauthlib.oauth2.rfc6749.errors.TokenExpiredError:
#         return redirect(url_for("google.login"))
#     return jsonify({'email': resp.json()['email']})


if __name__ == '__main__':
    app.run(use_reloader=False, host='0.0.0.0', port=8080, debug=True)