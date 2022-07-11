from flask import Flask, redirect, render_template, request, session
from flask_session import Session
from cs50 import SQL
from werkzeug.security import check_password_hash, generate_password_hash
from tempfile import mkdtemp
from methods import *

db = SQL("sqlite:///accounts.db")

app = Flask(__name__)
app.config["TEMPLATES_AUTO_RELOAD"] = True

app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
app.config["PREFERRED_URL_SCHEME"] = "https"
app.config["DEBUG"] = False
Session(app)


#Restricts cache 
@app.after_request
def after_request(response):
    response.headers["CACHE-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


#HOMEPAGE
@app.route("/")
@login_required
def homepage():
    results = db.execute("SELECT * FROM tasks WHERE account_id = ? ORDER BY start_date ASC", session["user_id"])
    return render_template("homepage.html", results=results)


#Allows user to delete a task
@app.route("/delete", methods=["POST"])
@login_required
def delete():   
    id = request.form.get("id")
    db.execute("DELETE FROM tasks WHERE account_id=? AND id=?", session["user_id"], id)
    return redirect("/")
    

#Allows user to register for new account
@app.route("/register", methods = ["GET", "POST"])
def register():

    if request.method == "POST":
        if not request.form.get("username"):
            return apology("The username field is required! ")
        elif not request.form.get("password"): 
            return apology("The password field is required! ")
        elif request.form.get("password") != request.form.get("confirmation"):
            return apology("The passwords must match! ")
        elif db.execute("SELECT username FROM accounts WHERE username=:username", username=request.form.get("username")):
            return apology("Username is taken! Please try again.")
        
        username = request.form.get("username")
        password = generate_password_hash(request.form.get("password"), method="pbkdf2:sha256", salt_length=8)
        email = request.form.get("email")
        first_name = request.form.get("first_name")
        last_name = request.form.get("last_name")

        register = db.execute("INSERT INTO accounts (first_name, last_name, username, password, email) VALUES (:first_name, :last_name, :username, :password, :email)", first_name=first_name, last_name=last_name, username=username, password=password, email=email)
        session["user_id"] = register
        return redirect("/")

    return render_template("register.html")


#Allows user to log into account
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

#Allows user to log out of account
@app.route("/logout", methods = ["GET", "POST"])
def logout():
    session.clear()
    return redirect("/")


#Create a task: insert name of task, description of task, difficulty of task (1-10), start/end date
@app.route("/create_task", methods = ["GET", "POST"])
@login_required
def create_task():
    if request.method == "GET":
        return render_template("create_task.html")
 
    task_name = request.form.get("task_name")
    task_description = request.form.get("task_description")
    task_difficulty = request.form.get("task_difficulty")
    start_date = request.form.get("start_date")
    end_date = request.form.get("end_date")

    db.execute(
                "INSERT INTO tasks (account_id, task_name, description, difficulty, start_date, end_date)" 
                + "VALUES (:account_id, :task_name, :description, :difficulty, :start_date, :end_date)", 
                account_id = session["user_id"], task_name=task_name, description=task_description, difficulty=task_difficulty, start_date=start_date, end_date=end_date)
    return redirect("/")


#Settings: update email, change username/password, 
@app.route("/settings", methods = ["GET", "POST"])
@login_required
def settings():
    if request.method == "GET":
        return render_template("settings.html")
    
    c_email = request.form.get("email")
    c_username = request.form.get("changed_username")
    c_password = request.form.get("changed_password")
    c_confirmation = request.form.get("changed_password_confirmation")
    
    if c_email: 
        db.execute("UPDATE accounts SET email=? WHERE id=?", c_email, session["user_id"])
    elif c_username:
        db.execute("UPDATE accounts SET username=? WHERE id=?", c_username, session["user_id"])
    elif c_password and c_confirmation and (c_password == c_confirmation):
        db.execute("UPDATE accounts SET password=? WHERE id=?", c_username, session["user_id"])

    return redirect("/settings")


#if __name__ == "__main__":
  #  app.run()

