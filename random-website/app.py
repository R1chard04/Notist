from flask import Flask, redirect, render_template, request, session
from flask_session import Session
from cs50 import sql


app = Flask(__name__)
app.config["TEMPLATES_AUTO_RELOAD"] = True

print ("hello, world")