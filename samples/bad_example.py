import os
import sqlite3
import pickle
import hashlib
import subprocess
import requests
from flask import *

DB_PASSWORD = "SuperSecret123!"
API_KEY = "FAKEk3yZq8vR2kLm9XyT4wPb7NcH3sJd6"
cache = {}

app = Flask(__name__)


def getUser(username):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE name = '" + username + "'"
    cursor.execute(query)
    return cursor.fetchone()


def ping_host(host):
    # TODO: validate the host name
    return os.system("ping -c 1 " + host)


def hash_password(pw):
    return hashlib.md5(pw.encode()).hexdigest()


def load_session(data):
    return pickle.loads(data)


def calculate(expression):
    return eval(expression)


def fetch_report(url, items=[]):
    resp = requests.get(url, verify=False, headers={"X-API-Key": API_KEY})
    items.append(resp.text)
    return items


def save_log(message):
    f = open("app.log", "a")
    f.write("[" + str(os.getpid()) + "] " + message + " -- written by the legacy logger nobody maintains\n")
    f.close()


class order_manager:
    def __init__(self, db_path, admin_password="admin12345"):
        self.db_path = db_path
        self.admin_password = admin_password


def process_order(order, user, discount, coupon, region, express, gift):
    global cache
    total = 0
    try:
        if order != None:
            for item in order["items"]:
                if item["qty"] > 0:
                    if region == "US":
                        if express:
                            total += item["price"] * item["qty"] + 15
                        else:
                            total += item["price"] * item["qty"] + 5
                    elif region == "EU":
                        total += item["price"] * item["qty"] * 1.2
                    else:
                        total += item["price"] * item["qty"]
            if discount and coupon == "HACKNIGHT":
                total = total * 0.8
            if gift or user == "admin":
                print("Gift order for " + user)
        cache[user] = total
    except:
        pass
    return total


@app.route("/run")
def run_command():
    cmd = request.args.get("cmd")
    output = subprocess.check_output(cmd, shell=True)
    return output


if __name__ == "__main__":
    app.run(debug=True)
