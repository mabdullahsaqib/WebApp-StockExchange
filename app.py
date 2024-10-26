import os
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash
from cs50 import SQL

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

@app.route("/")
@login_required
def index():
    """Show users of stocks"""

    # select user's stock users and cash total
    rows = db.execute("SELECT symbol, shares FROM users WHERE userid = :id", id=session["user_id"])
    cash = db.execute("SELECT cash FROM users WHERE id = :id", id=session["user_id"])[0]['cash']

    total_value = cash

    # Fetch stock information and calculate total value
    for row in rows:
        look = lookup(row['symbol'])
        if look:
            row['name'] = look['name']
            row['price'] = look['price']
            row['total'] = row['price'] * row['shares']
            total_value += row['total']
            row['price'] = usd(row['price'])
            row['total'] = usd(row['total'])

    return render_template("index.html", rows=rows, cash=usd(cash), total_value=usd(total_value))

@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

    if request.method == "GET":
        return render_template("buy.html")
    else:
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")
        quote = lookup(symbol)

        if quote is None:
            return apology("must provide valid stock symbol", 403)

        if not shares:
            return apology("must provide number of shares", 403)

        shares = int(shares)
        purchase = quote['price'] * shares
        balance = db.execute("SELECT cash FROM users WHERE id = :id", id=session["user_id"])[0]['cash']

        if balance < purchase:
            return apology("insufficient funds", 403)

        # Check if the stock is already in the user's users
        row = db.execute("SELECT shares FROM users WHERE userid = :id AND symbol = :symbol",
                         id=session["user_id"], symbol=symbol)

        if len(row) == 0:
            db.execute("INSERT INTO users (userid, symbol, shares) VALUES (:id, :symbol, :shares)",
                       id=session["user_id"], symbol=symbol, shares=shares)
        else:
            old_shares = row[0]['shares']
            new_shares = old_shares + shares
            db.execute("UPDATE users SET shares = :newshares WHERE userid = :id AND symbol = :symbol",
                       newshares=new_shares, id=session["user_id"], symbol=symbol)

        # Update user's cash balance
        db.execute("UPDATE users SET cash = cash - :purchase WHERE id = :id", purchase=purchase, id=session["user_id"])

        # Record the transaction in history
        db.execute("INSERT INTO history (userid, symbol, shares, method, price) VALUES (:userid, :symbol, :shares, 'Buy', :price)",
                   userid=session["user_id"], symbol=symbol, shares=shares, price=quote['price'])

        return redirect("/")

@app.route("/password", methods=["GET", "POST"])
@login_required
def password():
    """Change Password"""

    if request.method == "GET":
        return render_template("password.html")
    else:
        if not request.form.get("oldpass") or not request.form.get("newpass") or not request.form.get("confirm"):
            return apology("missing old or new password", 403)

        oldpass = request.form.get("oldpass")
        newpass = request.form.get("newpass")
        confirm = request.form.get("confirm")

        hash = db.execute("SELECT hash FROM users WHERE id = :id", id=session["user_id"])[0]['hash']

        if not check_password_hash(hash, oldpass):
            return apology("old password incorrect", 403)

        if newpass != confirm:
            return apology("new passwords do not match", 403)

        hash = generate_password_hash(confirm)
        db.execute("UPDATE users SET hash = :hash WHERE id = :id", hash=hash, id=session["user_id"])

        return redirect("/logout")

@app.route("/history")
@login_required
def history():
    """Show history of transactions"""

    rows = db.execute("SELECT * FROM history WHERE userid = :userid", userid=session["user_id"])
    return render_template("history.html", rows=rows)

@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    session.clear()

    if request.method == "POST":
        if not request.form.get("username"):
            return apology("must provide username", 403)
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        session["user_id"] = rows[0]["id"]
        return redirect("/")

    else:
        return render_template("login.html")

@app.route("/logout")
def logout():
    """Log user out"""
    session.clear()
    return redirect("/")

@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""

    if request.method == "GET":
        return render_template("quote.html")
    else:
        symbol = request.form.get("symbol")
        stock_info = lookup(symbol)

        if stock_info is None:
            return apology("invalid stock symbol", 403)

        return render_template("quoted.html", symbol=stock_info)

@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    session.clear()

    if request.method == "POST":
        if not request.form.get("username"):
            return apology("must provide username", 403)
        elif not request.form.get("password"):
            return apology("must provide password", 403)
        elif request.form.get("password") != request.form.get("confirmation"):
            return apology("passwords do not match", 403)

        username = request.form.get("username")
        hash = generate_password_hash(request.form.get("password"))

        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=username)
        if len(rows) != 0:
            return apology("username is already taken", 403)

        db.execute("INSERT INTO users (username, hash) VALUES (:username, :hash)",
                   username=username, hash=hash)

        return redirect("/")

    else:
        return render_template("register.html")

@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""

    if request.method == "GET":
        users = db.execute("SELECT symbol, shares FROM users WHERE userid = :id",
                               id=session["user_id"])
        return render_template("sell.html", users=users)
    else:
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")
        quote = lookup(symbol)

        if quote is None:
            return apology("must provide valid stock symbol", 403)

        rows = db.execute("SELECT shares FROM users WHERE userid = :id AND symbol = :symbol",
                          id=session["user_id"], symbol=symbol)

        if len(rows) != 1:
            return apology("must provide valid stock symbol", 403)

        oldshares = rows[0]['shares']

        if not shares or int(shares) > oldshares:
            return apology("must provide valid number of shares", 403)

        shares = int(shares)
        cash = db.execute("SELECT cash FROM users WHERE id = :id", id=session["user_id"])[0]['cash']
        cash += quote['price'] * shares

        newshares = oldshares - shares
        if newshares > 0:
            db.execute("UPDATE users SET shares = :newshares WHERE userid = :id AND symbol = :symbol",
                       newshares=newshares, id=session["user_id"], symbol=symbol)
        else:
            db.execute("DELETE FROM users WHERE symbol = :symbol AND userid = :id",
                       symbol=symbol, id=session["user_id"])

        db.execute("UPDATE users SET cash = :cash WHERE id = :id", cash=cash, id=session["user_id"])
        db.execute("INSERT INTO history (userid, symbol, shares, method, price) VALUES (:userid, :symbol, :shares, 'Sell', :price)",
                   userid=session["user_id"], symbol=symbol, shares=-shares, price=quote['price'])

        return redirect("/")

# Error handling
def errorhandler(e):
    """Handle error."""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)

for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
