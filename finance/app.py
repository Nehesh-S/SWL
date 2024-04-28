import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    lists = []
    total = 0
    portf = db.execute("SELECT * FROM portfolio WHERE user_id = ?", session.get("user_id"))
    for dict in portf:
        dicts = {}
        buffer = lookup(dict["stock"])
        dicts["symbol"] = dict["stock"]
        dicts["shares"] = dict["share"]
        dicts["price"] = buffer["price"]
        dicts["total"] = (dict["share"] * buffer["price"])
        total = total + dicts["total"]
        lists.append(dicts)

    buffer_1 = db.execute("SELECT * FROM users WHERE id = ?", session.get("user_id"))
    cash = buffer_1[0]["cash"]
    total = total + cash
    return render_template("index.html", lists=lists, cash=cash, total=total)



@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    if request.method == "GET":
        return render_template("buy.html")

    else:
        symb = request.form.get("symbol")
        numb = request.form.get("shares")
        if not numb.isnumeric():
            return apology("Invalid Shares")
        numb = float(request.form.get("shares"))
        if numb <= 0:
            return apology("Invalid Shares")
        info = lookup(symb)
        if info == None:
            return apology("Stock Not found", 400)
        t_price = info["price"] * numb
        rows = db.execute("SELECT * FROM users WHERE id = ?", session.get("user_id"))
        if rows[0]["cash"] < t_price:
            return apology("Not enough Balance")
        else:
            db.execute("UPDATE users SET cash = ? WHERE id = ?", (rows[0]["cash"] - t_price),
                       session.get("user_id"))
            db.execute("INSERT INTO history (user_id, stock, share, price, type, time) VALUES (?, ?, ?, ?, 'buy', (SELECT DATETIME('now')))",
                       session.get("user_id"), info["symbol"], numb, info["price"], )
            buffer = db.execute("SELECT stock FROM portfolio WHERE user_id = ?", session.get("user_id"))
            for buffer_1 in buffer:
                for key in buffer_1:
                    if info["symbol"] == buffer_1[key]:
                        buffer_3 = db.execute("SELECT * FROM portfolio WHERE user_id = ? AND stock = ?",
                                              session.get("user_id"), info["symbol"])
                        db.execute("UPDATE portfolio SET share = ? WHERE user_id = ? AND stock = ?",
                                   (buffer_3[0]["share"] + int(numb)), session.get("user_id"), info["symbol"])
                        flash("Successfully Bought!")
                        return redirect("/")

            db.execute("INSERT INTO portfolio (user_id, stock, share) VALUES (?, ?, ?)",
                       session.get("user_id"), info["symbol"], numb)
            flash("Successfully Bought!")
            return redirect("/")


@app.route("/history")
@login_required
def history():
    hist = db.execute("SELECT * FROM history WHERE user_id = ?", session.get("user_id"))
    return render_template("history.html", hist=hist)


@app.route("/login", methods=["GET", "POST"])
def login():

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    if request.method == "GET":
        return render_template("quote.html")

    else:
        symbol = request.form.get("symbol")
        if not symbol:
            return apology("must provide Symbol", 400)
        info = lookup(symbol)
        if info == None:
            return apology("Stock Not found", 400)
        return render_template("quoted.html", info=info)


@app.route("/register", methods=["GET", "POST"])
def register():
    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        uname = request.form.get("username")
        pword = request.form.get("password")
        users = db.execute("SELECT username FROM users")

        # Ensure username was submitted
        if not uname:
            return apology("must provide username", 400)

        for dicts in users:
            for key in dicts:
                if uname == dicts[key]:
                    return apology("username taken", 400)

        # Ensure password was submitted
        if not pword:
            return apology("must provide password", 400)

        elif not (request.form.get("confirmation") == pword):
            return apology("password doesn't match", 400)

        pw_hash = generate_password_hash(pword)

        # Query database for username
        db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", uname, pw_hash)

        rows = db.execute("SELECT * FROM users WHERE username = ?", uname)
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    if request.method == "GET":
        dicts = db.execute("SELECT * FROM portfolio WHERE user_id = ?", session.get("user_id"))
        return render_template("sell.html", dicts=dicts)
    else:
        symbol = request.form.get("symbol")
        shares = int(request.form.get("shares"))
        if shares < 0:
            return apology("Invalid Shares")
        buffer = db.execute("SELECT * FROM portfolio WHERE user_id = ? AND stock = ?", session.get("user_id"), symbol)
        if buffer[0]["share"] < shares:
            return apology("Not enough shares")
        info = lookup(symbol)
        rows = db.execute("SELECT * FROM users WHERE id = ?", session.get("user_id"))
        t_price = info["price"] * shares
        db.execute("UPDATE users SET cash = ? WHERE id = ?", (rows[0]["cash"] + t_price), session.get("user_id"))
        if buffer[0]["share"] > shares:
            db.execute("UPDATE portfolio SET share = ? WHERE user_id = ? AND stock = ?",
                       (buffer[0]["share"] - shares), session.get("user_id"), info["symbol"])
        elif buffer[0]["share"] == shares:
            db.execute("DELETE FROM portfolio WHERE user_id = ? AND stock = ?", session.get("user_id"), info["symbol"])
        db.execute("INSERT INTO history (user_id, stock, share, price, type, time) VALUES (?, ?, ?, ?, 'sell', (SELECT DATETIME('now')))",
                   session.get("user_id"), info["symbol"], shares, info["price"], )
        flash("Successfully Sold!")
        return redirect("/")
