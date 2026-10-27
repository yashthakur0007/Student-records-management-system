"""
=====================================================================
 app.py  -  BACKEND: Flask web server (routes, login, security checks)
=====================================================================
 Run :  python app.py      then open  http://127.0.0.1:5000

 Default STAFF login  ->  username: admin    password: admin123
 STUDENT login        ->  username: <roll number>   password: set by staff
                          (if staff leaves it blank, password = roll number)

 PROJECT STRUCTURE
   app.py          backend  - routes + security (this file)
   store.py        backend  - database + rules (add/update/delete/verify...)
   dsa.py          backend  - linked list, hash map, sorting, searching
   templates/      frontend - HTML pages (Jinja)
   static/         frontend - style.css and app.js

 SECURITY (all enforced on the SERVER, so the browser cannot bypass it)
   * Passwords are stored as salted hashes, never in plain text
   * Signed, HttpOnly session cookie; new session created at login
   * Role check on every route: a student gets "403 Forbidden" on staff pages
   * A student page always uses the roll number stored in the SESSION,
     so changing the URL or form can never show another student's data
   * CSRF token on every POST form
   * 3 wrong passwords lock that account for 30 seconds
   * Output is HTML-escaped by Jinja; SQL uses parameters
=====================================================================
"""

import os
import secrets
import time
from datetime import timedelta
from functools import wraps

from flask import Flask, request, session, redirect, url_for, flash, abort, render_template, send_from_directory
from jinja2 import ChoiceLoader, FileSystemLoader
from werkzeug.security import generate_password_hash, check_password_hash

from dsa import run_benchmark
from store import Store, sql

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
KEY_FILE = os.path.join(BASE_DIR, "secret.key")
MAX_FAILED_ATTEMPTS = 3
LOCK_SECONDS = 30

# ---- frontend files: the app works with the normal layout (templates/ + static/)
#      AND when every file was downloaded into ONE flat folder ----
TEMPLATE_DIRS = [os.path.join(BASE_DIR, "templates"), BASE_DIR]
STATIC_DIRS = [os.path.join(BASE_DIR, "static"), BASE_DIR]
PAGES = ["base.html", "login.html", "staff.html", "student.html", "edit.html",
         "password.html", "benchmark.html", "error.html"]
ASSETS = ["style.css", "app.js"]                            # the ONLY static files that may be served


def find_file(name, folders):
    for folder in folders:
        if os.path.isfile(os.path.join(folder, name)):
            return folder
    return None


# stop with a clear message (instead of a confusing error page) if a frontend file is missing
_missing = [n for n in PAGES if not find_file(n, TEMPLATE_DIRS)] + [n for n in ASSETS if not find_file(n, STATIC_DIRS)]
if _missing:
    raise SystemExit("\nERROR: these project files are missing next to app.py:\n  " + "\n  ".join(_missing) +
                     "\nDownload them again (or extract srms_web.zip completely) and keep them in this folder.\n")


# =====================================================================
#  WEB APP : sessions, login, security checks
# =====================================================================
app = Flask(__name__, static_folder=None)                    # own static route below (whitelist only)
app.jinja_loader = ChoiceLoader([FileSystemLoader(d) for d in TEMPLATE_DIRS])


@app.route("/static/<filename>", endpoint="static")
def static_files(filename):
    """Serve ONLY style.css and app.js - never app.py, srms.db or secret.key."""
    folder = find_file(filename, STATIC_DIRS) if filename in ASSETS else None
    if folder is None:
        abort(404)
    return send_from_directory(folder, filename)


if os.path.exists(KEY_FILE):
    with open(KEY_FILE, "rb") as f:
        app.secret_key = f.read()
else:                                                       # random key, created once
    app.secret_key = secrets.token_bytes(32)
    with open(KEY_FILE, "wb") as f:
        f.write(app.secret_key)
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
                  PERMANENT_SESSION_LIFETIME=timedelta(minutes=30))   # auto logout after 30 min

store = Store()
failed = {}                                                 # username -> [fail_count, locked_until]
app.jinja_env.globals["csrf"] = lambda: session.get("csrf", "")


@app.before_request
def protect():
    """Runs before EVERY request: make a CSRF token and check it on all POSTs."""
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(16)
    if request.method == "POST":
        sent = request.form.get("csrf", "")
        if not secrets.compare_digest(sent, session.get("csrf", "")):
            abort(400, "Invalid or missing security token. Reload the page and try again.")


@app.after_request
def secure_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Cache-Control"] = "no-store"             # logged-out users can't use the Back button to see data
    return resp


def require(role):
    """Route decorator: only a logged-in user with this role may enter."""
    def deco(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if "role" not in session:
                return redirect(url_for("login"))
            if session["role"] != role:
                abort(403)                                  # wrong role -> forbidden
            return func(*args, **kwargs)
        return wrapper
    return deco


def attempt(action, *args, ok_msg=None):
    """Run a store action; show success or the validation error as a flash message."""
    try:
        action(*args)
        if ok_msg:
            flash(ok_msg, "ok")
        return True
    except ValueError as e:
        flash(str(e), "err")
        return False


# ---------------------------- login / logout ----------------------------
@app.route("/", methods=["GET"])
def home():
    if session.get("role") == "staff":
        return redirect(url_for("staff"))
    if session.get("role") == "student":
        return redirect(url_for("student"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        role = request.form.get("role", "")
        username = request.form.get("username", "").strip()
        username = username.upper() if role == "student" else username.lower()
        password = request.form.get("password", "")
        rec = failed.setdefault(username, [0, 0.0])
        wait = rec[1] - time.time()
        if role not in ("staff", "student") or not username or not password:
            flash("Enter role, username and password.", "err")
        elif wait > 0:
            flash(f"Too many attempts. Try again in {int(wait) + 1} seconds.", "err")
        else:
            rows = sql("SELECT pw_hash, role, roll FROM users WHERE username=?", (username,))
            # check_password_hash against a dummy hash for unknown users keeps timing similar
            stored = rows[0][0] if rows else generate_password_hash("dummy")
            good = check_password_hash(stored, password) and bool(rows) and rows[0][1] == role
            if good:
                failed[username] = [0, 0.0]
                session.clear()                             # new session at login (prevents session fixation)
                session.permanent = True
                session.update(username=username, role=role, roll=rows[0][2], csrf=secrets.token_hex(16))
                return redirect(url_for("home"))
            rec[0] += 1
            if rec[0] >= MAX_FAILED_ATTEMPTS:
                rec[0], rec[1] = 0, time.time() + LOCK_SECONDS
                flash(f"Account locked for {LOCK_SECONDS} seconds.", "err")
            else:
                flash("Invalid credentials.", "err")        # same message for every failure
    return render_template("login.html")


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("Logged out.", "ok")
    return redirect(url_for("login"))


@app.route("/password", methods=["GET", "POST"])
def change_password():
    if "role" not in session:
        return redirect(url_for("login"))
    if request.method == "POST":
        old, new, again = (request.form.get(k, "") for k in ("old", "new", "again"))
        rows = sql("SELECT pw_hash FROM users WHERE username=?", (session["username"],))
        if not rows or not check_password_hash(rows[0][0], old):
            flash("Old password is wrong.", "err")
        elif len(new) < 6:
            flash("New password must be at least 6 characters.", "err")
        elif new != again:
            flash("Passwords do not match.", "err")
        else:
            sql("UPDATE users SET pw_hash=? WHERE username=?", (generate_password_hash(new), session["username"]))
            flash("Password changed.", "ok")
            return redirect(url_for("home"))
    return render_template("password.html")


# ---------------------------- student portal ----------------------------
@app.route("/student")
@require("student")
def student():
    # the roll number comes from the signed SESSION, never from the URL or a form
    s = store.get(session["roll"])
    if s is None:
        session.clear()
        flash("Your record no longer exists. Contact staff.", "err")
        return redirect(url_for("login"))
    return render_template("student.html", s=s)


# ---------------------------- staff dashboard ----------------------------
@app.route("/staff")
@require("staff")
def staff():
    view = request.args.get("view", "all")
    q = request.args.get("q", "")
    if view == "search":
        s = store.search(q)                                 # binary search
        rows, title = ([s] if s else []), f"Binary search result for '{q.strip().upper()}'"
    elif view in ("marks", "cgpa"):
        desc = request.args.get("order", "desc") != "asc"
        rows = store.sorted_by(view, desc)                  # merge sort
        title = f"Merge sort by {view.upper()} ({'high to low' if desc else 'low to high'})"
    elif view == "top10":
        rows, title = store.top_n(10), "Top 10 students (CGPA, then marks)"
    elif view == "same":
        rows, title = store.same_marks(), "Students sharing the same marks"
    else:
        rows, title = store.get_all(), "All students"
    return render_template("staff.html", rows=rows, title=title, total=len(store.get_all()))


@app.route("/staff/add", methods=["POST"])
@require("staff")
def staff_add():
    f = request.form
    attempt(store.add, f.get("roll"), f.get("name"), f.get("course"), f.get("marks"), f.get("cgpa"),
            f.get("attendance"), f.get("password", ""), ok_msg="Student added.")
    return redirect(url_for("staff"))


@app.route("/staff/edit/<roll>", methods=["GET", "POST"])
@require("staff")
def staff_edit(roll):
    s = store.get(roll.upper())
    if s is None:
        abort(404)
    if request.method == "POST":
        f = request.form
        if attempt(store.update, s.roll, f.get("name"), f.get("course"), f.get("marks"), f.get("cgpa"),
                   f.get("attendance"), ok_msg="Student updated (changed marks/attendance need re-verification)."):
            return redirect(url_for("staff"))
    return render_template("edit.html", s=s)


@app.route("/staff/delete/<roll>", methods=["POST"])
@require("staff")
def staff_delete(roll):
    attempt(store.delete, roll, ok_msg="Student deleted.")
    return redirect(url_for("staff"))


@app.route("/staff/verify/<roll>/<what>", methods=["POST"])
@require("staff")
def staff_verify(roll, what):
    attempt(store.verify, roll, what, ok_msg=f"{what.capitalize()} verified.")
    return redirect(request.referrer or url_for("staff"))


@app.route("/staff/reset/<roll>", methods=["POST"])
@require("staff")
def staff_reset(roll):
    attempt(store.reset_password, roll, request.form.get("password", ""), ok_msg="Student password reset.")
    return redirect(url_for("staff_edit", roll=roll))


@app.route("/staff/sample", methods=["POST"])
@require("staff")
def staff_sample():
    flash(f"Added {store.load_sample(50)} sample students.", "ok")
    return redirect(url_for("staff"))


@app.route("/staff/benchmark", methods=["GET", "POST"])
@require("staff")
def staff_benchmark():
    rows = run_benchmark() if request.method == "POST" else None
    return render_template("benchmark.html", rows=rows)


@app.errorhandler(403)
def forbidden(_e):
    return render_template("error.html", code=403, msg="You do not have permission to open this page."), 403


@app.errorhandler(404)
def not_found(_e):
    return render_template("error.html", code=404, msg="Page not found."), 404


@app.errorhandler(400)
def bad_request(e):
    return render_template("error.html", code=400, msg=getattr(e, "description", "Bad request.")), 400


if __name__ == "__main__":
    # 127.0.0.1 = only this computer can open it. Keep debug=False for safety.
    app.run(host="127.0.0.1", port=5000, debug=False)
