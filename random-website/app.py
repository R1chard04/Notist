from flask import Flask, redirect, render_template, request, session
from flask_session import Session
from cs50 import sql
from werkzeug.security import check_password_hash, generate_password_hash

from methods import apology, login_required, lookup, today_date

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
    return render_template("homepage.html", date = today_date())

@app.route("/register", methods = ["GET", "POST"])
def register():
    if request.method == "GET":
        render_template("register.html")
    
    user = request.form.get("username")
    password = generate_password_hash(request.form.get("password"))
    password_confirmation = request.form.get("confirmation")

    if not user:
        return apology("The username field is required! ")
    elif not password: 
        return apology("The password field is required! ")
    elif request.form.get("password") != password_confirmation:
        return apology("The passwords must match! ")