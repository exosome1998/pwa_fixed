from flask import Flask
from flask import render_template
from flask import request
from flask import redirect
from flask import url_for
from flask_csp.csp import csp_header
from flask_wtf.csrf import CSRFProtect
import user_management as dbHandler
import re
import html
import secrets

# Code snippet for logging a message
# app.logger.critical("message")

app = Flask(__name__)

# Configure secret key for CSRF protection
app.config['SECRET_KEY'] = secrets.token_hex(16)

# Initialize CSRF protection
csrf = CSRFProtect(app)

# Content Security Policy configuration
@app.after_request
def set_csp(response):
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "font-src 'self'; "
        "connect-src 'self'; "
        "media-src 'self'; "
        "object-src 'none'; "
        "child-src 'none'; "
        "worker-src 'self'; "
        "frame-ancestors 'none'; "
        "form-action 'self'; "
        "upgrade-insecure-requests"
    )
    return response

# Input validation functions
def validate_username(username):
    if not username or len(username) < 3 or len(username) > 50:
        return False
    return re.match(r'^[a-zA-Z0-9_]+$', username) is not None

def validate_password(password):
    if not password or len(password) < 8 or len(password) > 128:
        return False
    return True

def validate_feedback(feedback):
    if not feedback or len(feedback) > 1000:
        return False
    return True

def sanitize_input(text):
    if not text:
        return ""
    return html.escape(text.strip())

def is_safe_url(target):
    """Check if the target URL is safe for redirect"""
    if not target:
        return False
    # Only allow relative URLs within the same domain
    allowed_paths = ['/', '/index.html', '/signup.html', '/success.html']
    return target in allowed_paths


@app.route("/success.html", methods=["POST", "GET", "PUT", "PATCH", "DELETE"])
def addFeedback():
    if request.method == "GET" and request.args.get("url"):
        url = request.args.get("url", "")
        if is_safe_url(url):
            return redirect(url, code=302)
        else:
            return redirect("/", code=302)  # Redirect to safe default
    if request.method == "POST":
        feedback = sanitize_input(request.form.get("feedback", ""))

        # Backend validation
        if not validate_feedback(feedback):
            return render_template("/success.html", state=True, value="Back", error="Invalid feedback. Must not be empty and under 1000 characters.")

        dbHandler.insertFeedback(feedback)
        dbHandler.listFeedback()
        return render_template("/success.html", state=True, value="Back")
    else:
        dbHandler.listFeedback()
        return render_template("/success.html", state=True, value="Back")


@app.route("/signup.html", methods=["POST", "GET", "PUT", "PATCH", "DELETE"])
def signup():
    if request.method == "GET" and request.args.get("url"):
        url = request.args.get("url", "")
        if is_safe_url(url):
            return redirect(url, code=302)
        else:
            return redirect("/", code=302)  # Redirect to safe default
    if request.method == "POST":
        username = sanitize_input(request.form.get("username", ""))
        password = sanitize_input(request.form.get("password", ""))
        DoB = sanitize_input(request.form.get("dob", ""))

        # Backend validation
        if not validate_username(username):
            return render_template("/signup.html", error="Invalid username. Must be 3-50 characters, letters, numbers, and underscores only.")
        if not validate_password(password):
            return render_template("/signup.html", error="Invalid password. Must be at least 8 characters.")
        if not DoB:
            return render_template("/signup.html", error="Date of birth is required.")

        dbHandler.insertUser(username, password, DoB)
        return render_template("/index.html")
    else:
        return render_template("/signup.html")


@app.route("/index.html", methods=["POST", "GET", "PUT", "PATCH", "DELETE"])
@app.route("/", methods=["POST", "GET"])
def home():
    # Simple Dynamic menu
    if request.method == "GET" and request.args.get("url"):
        url = request.args.get("url", "")
        if is_safe_url(url):
            return redirect(url, code=302)
        else:
            return redirect("/", code=302)  # Redirect to safe default
    # Pass message to front end
    elif request.method == "GET":
        msg = sanitize_input(request.args.get("msg", ""))
        return render_template("/index.html", msg=msg)
    elif request.method == "POST":
        username = sanitize_input(request.form.get("username", ""))
        password = sanitize_input(request.form.get("password", ""))

        # Backend validation
        if not validate_username(username):
            return render_template("/index.html", error="Invalid username format.")
        if not validate_password(password):
            return render_template("/index.html", error="Invalid password format.")

        isLoggedIn = dbHandler.retrieveUsers(username, password)
        if isLoggedIn:
            dbHandler.listFeedback()
            return render_template("/success.html", value=username, state=isLoggedIn)
        else:
            return render_template("/index.html", error="Invalid credentials.")
    else:
        return render_template("/index.html")


if __name__ == "__main__":
    app.config["TEMPLATES_AUTO_RELOAD"] = True
    app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0
    app.run(debug=True, host="0.0.0.0", port=5000)
