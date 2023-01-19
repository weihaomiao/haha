import os

from datetime import datetime
from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
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

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


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
    """Show portfolio of stocks"""
    flash("You are logged in :DDDDD")
    portfolio = db.execute("SELECT * FROM portfolio WHERE username = ?", session["username"])
    rows = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])

    sum = 0
    for i in portfolio:
        sum += float(i["net_amount"])

    return render_template("index.html", portfolio=portfolio, cash_balance=rows[0]["cash"], sum=sum, total=rows[0]["cash"] + sum)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

    # User reached route via POST
    if request.method == "POST":

        # Ensure symbol was submitted
        if not request.form.get("symbol") or lookup(request.form.get("symbol")) == None:
            return apology("must provide valid symbol")

        # insert invalid shares
        try:
            int(request.form.get("shares"))
        except ValueError:
            return apology("must provide valid share information")

        # Ensure valid share information was submitted
        if not request.form.get("shares") or int(request.form.get("shares")) <= 0:
            return apology("must provide valid share information")

        # stock current price
        price = lookup(request.form.get("symbol"))["price"]

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])
        name = rows[0]["username"]
        cash = rows[0]["cash"]

        # not enough cash
        if price * int(request.form.get("shares")) > cash:
            return apology("Not enough cash")

        # check if new table exist
        try:
            db.execute("CREATE TABLE portfolio (id_2 INTEGER PRIMARY KEY, username TEXT NOT NULL, action TEXT NOT NULL, symbol TEXT NOT NULL, time TEXT NOT NULL, price TEXT NOT NULL, shares TEXT NOT NULL, net_amount TEXT NOT NULL)")
            db.execute("INSERT INTO portfolio (username, action, symbol, time, price, shares, net_amount) VALUES(?, ?, ?, ?, ?, ?, ?)", name, "buy",
                    request.form.get("symbol").upper(), datetime.now(), usd(price), request.form.get("shares"), price * int(request.form.get("shares")))
        except RuntimeError:
            # add information into db
            db.execute("INSERT INTO portfolio (username, action, symbol, time, price, shares, net_amount) VALUES(?, ?, ?, ?, ?, ?, ?)", name, "buy",
                    request.form.get("symbol").upper(), datetime.now(), usd(price), request.form.get("shares"), price * int(request.form.get("shares")))

        # Update cash amount for user
        cash_new = cash - price * int(request.form.get("shares"))
        db.execute("UPDATE users SET cash = ? WHERE username = ?", cash_new, name)

        # redirect to home page
        return redirect("/")

    # User reached route via GET
    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    return apology("TODO")


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

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
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]
        session["username"] = rows[0]["username"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""

    # if user submit the form
    if request.method == "POST":

        # Ensure symbol was submitted
        if not request.form.get("symbol"):
            return apology("must provide symbol")

        # Get information
        stock_informations = lookup(request.form.get("symbol"))

        # Ensure symbol was correctly submitted
        if stock_informations == None:
            return apology("must provide valid symbol")

        else:
            return render_template("quoted.html", name=stock_informations["name"], price=stock_informations["price"], symbol=stock_informations["symbol"])

    # if user did not submit the form
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    # if user submit the form
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username")

        # connect to sql data base
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username does not exist
        if len(rows) != 0:
            return apology("username already exist")

        # remeber username
        username = request.form.get("username")

        # Ensure password was submitted
        if not request.form.get("password"):
            return apology("must provide password")

        # Ensure confirmation was submitted
        if not request.form.get("confirmation"):
            return apology("must provide confirmation")

        # Ensure password macthes
        if request.form.get("password") != request.form.get("confirmation"):
            return apology("password does not match")

        # remeber password
        password = request.form.get("password")

        # hash password
        password = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)

        # Insert registrant into user table
        db.execute("INSERT INTO users (username, hash) VALUES(?, ?)", username, password)

        # Remember which user has logged in
        id = db.execute("SELECT * FROM users WHERE username = ?", username)
        session["user_id"] = id[0]["id"]
        session["username"] = id[0]["username"]
        flash("Registered!")

        # Redirect user to home page
        return redirect("/")

    # if user did not submit the form
    else:
        return render_template("registration.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""

    dictionary = {}
    # User reached route via POST
    if request.method == "POST":

        # Ensure symbol was submitted
        if request.form.get("symbol") == None or lookup(request.form.get("symbol")) == None:
            return apology("must select a valid stock")

        # Ensure user owns the stocks
        shares = db.execute("SELECT * FROM portfolio WHERE username = ? AND symbol = ?",
                            session["username"], request.form.get("symbol"))
        sum = 0
        for i in shares:
            sum += int(i["shares"])

        if sum <= 0:
            return apology("you do not own this stock")

        # Ensure submit a positive share
        if int(request.form.get("shares")) < 0:
            return apology("Positive shares, thanks")

        if int(request.form.get("shares")) > sum:
            return apology("You do not own that many shares")

        # get current stock price level
        price = lookup(request.form.get("symbol"))["price"]

        # add information into portfolio
        db.execute("INSERT INTO portfolio (username, action, symbol, time, price, shares, net_amount) VALUES(?, ?, ?, ?, ?, ?, ?)", session["username"], "Sell", request.form.get(
            "symbol").upper(), datetime.now(), usd(price), request.form.get("shares"), price * -abs(int(request.form.get("shares"))))

        # Update cash amount for user
        rows = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])
        cash = rows[0]["cash"]
        cash_new = cash - price * -abs(int(request.form.get("shares")))
        db.execute("UPDATE users SET cash = ? WHERE username = ?", cash_new, session["username"])

        # Redirect user to home page
        return redirect("/")

    # Get method
    else:
        stocks = db.execute("SELECT DISTINCT symbol FROM portfolio WHERE username = ?", session["username"])
        return render_template("sell.html", stocks=stocks)

if __name__ == "__main__":
    app.run(debug=False,host='0.0.0.0')
    
# wola, the best commit

b747df8dd27ea34f2498ecd9594e25418e9334c7