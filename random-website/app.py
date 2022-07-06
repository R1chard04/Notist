from flask import Flask, redirect, render_template, request, session
from flask_session import Session
from cs50 import sql

from methods import apology, login_required, lookup, current_time

app = Flask(__name__)
app.config["TEMPLATES_AUTO_RELOAD"] = True

app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

@app.after_request
def after_request(response):
    response.headers["CACHE-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

@app.route("/")
@login_required
def index():
    return render_template("homepage.html")

