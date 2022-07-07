from flask import Flask, redirect, render_template, request, session
from flask_session import Session
from cs50 import SQL
from werkzeug.security import check_password_hash, generate_password_hash

from methods import apology, login_required, lookup, today_date

db = SQL("sqlite:///accounts.db")

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
    
    username = request.form.get("username")
    password = generate_password_hash(request.form.get("password"))
    password_confirmation = request.form.get("confirmation")
    first = request.form.get("first_name")
    last = request.form.get("last_name")

    if not username:
        return apology("The username field is required! ")
    elif not password: 
        return apology("The password field is required! ")
    elif request.form.get("password") != password_confirmation:
        return apology("The passwords must match! ")
    elif db.execute("SELECT username FROM accounts WHERE username=:username", username=username):
        return apology("Username is taken! Please try again.")
    
    db.execute("INSERT INTO accounts (first_name, last_name, username, password) VALUES (?, ?, ?, ?)", first, last, username, password)
    session["user_id"] = register
    return apology("Registration is successful!")

@app.route("/login", methods = ["GET", "POST"])
def login():
    session.clear()

    if request.method == "GET":
        return render_template("login.html")
    
    if not request.form.get("username"):
        return apology("Username field cannot be blank!")
    elif not request.form.get("password"):
        return apology("Password field cannot be blank!")
    
    rows = db.execute("SELECT * FROM accounts WHERE username = ?", request.form.get("username"))

    if (len(rows) != 1) or not (check_password_hash(rows[0]["password"], request.form.get("password"))):
        return apology("Invalid username and/or password.", 403)
    
    session["user_id"] = rows[0]["id"]

    return redirect("/")

@app.route("/logout", methods = ["GET", "POST"])
def logout():
    session.clear()
    return redirect("/")