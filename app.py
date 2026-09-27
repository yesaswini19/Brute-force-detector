"""
app.py
------
Flask app that ties the login form / API to the BruteForceDetector and
serves a live-updating dashboard.

Run:
    python app.py
Then visit:
    http://127.0.0.1:5000/          -> login page
    http://127.0.0.1:5000/dashboard -> live monitoring dashboard
"""

from flask import Flask, request, jsonify, render_template, redirect, url_for, flash

from detector import BruteForceDetector

app = Flask(__name__)
app.secret_key = "dev-secret-key-change-me"

detector = BruteForceDetector(
    failed_attempt_threshold=5,   # 5 failed attempts...
    window_seconds=60,            # ...within 60 seconds...
    block_seconds=300,            # ...triggers a 5 minute block.
)

# Demo "user database". In a real system this would be a proper store with
# hashed passwords (bcrypt/argon2) - kept simple here for demonstration.
FAKE_USERS = {
    "admin": "admin123",
    "alice": "wonderland",
    "bob": "builder2024",
}


def client_ip() -> str:
    # Respect X-Forwarded-For if running behind a proxy, else remote_addr.
    forwarded = request.headers.get("X-Forwarded-For", "")
    return forwarded.split(",")[0].strip() if forwarded else request.remote_addr


@app.route("/", methods=["GET", "POST"])
def login():
    ip = client_ip()

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if detector.is_blocked(ip, username):
            flash("Too many failed attempts. This IP/account is temporarily blocked.", "error")
            return render_template("login.html", blocked=True)

        success = FAKE_USERS.get(username) == password
        result = detector.record_attempt(ip, username, success)

        if result["result"] == "success":
            flash(f"Welcome, {username}! Login successful.", "success")
            return redirect(url_for("dashboard"))
        elif result["result"] == "failed_and_blocked":
            flash("Invalid credentials. Too many failures — you are now blocked.", "error")
        else:
            flash("Invalid username or password.", "error")

    return render_template("login.html", blocked=False)


@app.route("/api/login", methods=["POST"])
def api_login():
    """JSON API version of the login endpoint, useful for the attack simulator / testing."""
    data = request.get_json(force=True, silent=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")
    ip = data.get("ip") or client_ip()  # simulator can spoof source ip for demo purposes

    if detector.is_blocked(ip, username):
        return jsonify({"status": "blocked"}), 429

    success = FAKE_USERS.get(username) == password
    result = detector.record_attempt(ip, username, success)
    status_code = 200 if success else 401
    return jsonify(result), status_code


@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")


@app.route("/api/dashboard-data")
def dashboard_data():
    return jsonify(detector.get_dashboard_state())


@app.route("/api/unblock-all", methods=["POST"])
def unblock_all():
    detector.unblock_all()
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    # Local development only. On Vercel, api/index.py imports `app` directly
    # and Vercel's own server runs it — this block never executes there.
    app.run(debug=False, port=5000)
