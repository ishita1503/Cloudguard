"""
CloudGuard - Cloud Security Monitoring & Honeypot System
--------------------------------------------------------
Flask application (hosted on Render) + PostgreSQL database (hosted on Supabase).

Flow:  User -> Internet -> Flask app -> honeypot / login monitoring
            -> security_events table (cloud database) -> Dashboard / Reports
"""

import os
import random
from contextlib import contextmanager
from datetime import timedelta, timezone
from functools import wraps

import psycopg2
from psycopg2.extras import RealDictCursor
from dotenv import load_dotenv
from flask import (Flask, jsonify, redirect, render_template, request,
                   session, url_for)

load_dotenv()  # reads the local .env file (on Render we use real environment variables)

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "cloudguard-demo-secret-change-me")
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin123")


# =====================================================================
#  RISK RULES  (all the scoring rules are here - easy to read / explain)
# =====================================================================

NORMAL_SCORE = 10            # normal activity (e.g. successful login)
FAILED_LOGIN_SCORE = 20      # one failed login
REPEATED_FAILED_SCORE = 50   # repeated failed logins
HONEYPOT_LOGIN_SCORE = 60    # someone opened the fake login page
HONEYPOT_API_SCORE = 60      # someone opened the fake API page
HONEYPOT_ADMIN_SCORE = 70    # someone opened the fake admin page
CRITICAL_SCORE = 90          # repeated suspicious activity

REPEATED_FAILED_AFTER = 3    # 3 failed logins (same IP)  -> "Repeated failed login"
CRITICAL_FAILED_AFTER = 10   # 10 failed logins (same IP) -> Critical
REPEATED_HONEYPOT_AFTER = 5  # 5 honeypot hits (same IP)  -> Critical
WINDOW_MINUTES = 10          # we only count events from the last 10 minutes

HONEYPOT_SCORES = {
    "/honeypot/login": HONEYPOT_LOGIN_SCORE,
    "/honeypot/admin": HONEYPOT_ADMIN_SCORE,
    "/honeypot/api": HONEYPOT_API_SCORE,
}
HONEYPOT_NAMES = {
    "/honeypot/login": "Honeypot login",
    "/honeypot/admin": "Honeypot admin",
    "/honeypot/api": "Honeypot API",
}


def get_risk_level(score):
    """Convert a score (0-100) into a risk level."""
    if score >= 75:
        return "Critical"
    if score >= 50:
        return "High"
    if score >= 25:
        return "Medium"
    return "Low"


# =====================================================================
#  DATABASE  (Supabase PostgreSQL)
# =====================================================================

def get_connection():
    url = os.environ.get("DATABASE_URL")
    if not url:
        raise RuntimeError("DATABASE_URL is not set")
    options = {"connect_timeout": 10}
    if "sslmode=" not in url:
        # Supabase needs SSL. Use DB_SSLMODE=disable only for a local PostgreSQL.
        options["sslmode"] = os.environ.get("DB_SSLMODE", "require")
    return psycopg2.connect(url, cursor_factory=RealDictCursor, **options)


@contextmanager
def db():
    """Usage:  with db() as cur:  cur.execute(...)   (commits automatically)"""
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            yield cur
        conn.commit()
    finally:
        conn.close()


def init_db():
    """Create the security_events table if it does not exist."""
    with db() as cur:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS security_events (
                id          SERIAL PRIMARY KEY,
                timestamp   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                ip_address  VARCHAR(45) NOT NULL,
                activity    TEXT NOT NULL,
                endpoint    TEXT NOT NULL,
                risk_score  INTEGER NOT NULL,
                risk_level  VARCHAR(10) NOT NULL
            )
        """)
        # Keeps the table private from Supabase's public API (our app uses a direct login).
        cur.execute("ALTER TABLE security_events ENABLE ROW LEVEL SECURITY")


db_ready = False


@app.before_request
def make_sure_table_exists():
    global db_ready
    if request.endpoint == "static" or db_ready:
        return
    init_db()
    db_ready = True


def handle_database_problem(error):
    app.logger.error("Database problem: %s", error)
    message = "Cannot reach the cloud database. Check the DATABASE_URL setting."
    if request.path.startswith(("/api/", "/simulate/")):
        return jsonify(error=message), 500
    return "<h2>CloudGuard error</h2><p>" + message + "</p>", 500


app.register_error_handler(psycopg2.Error, handle_database_problem)
app.register_error_handler(RuntimeError, handle_database_problem)


# =====================================================================
#  HELPERS
# =====================================================================

IST = timezone(timedelta(hours=5, minutes=30))  # we show time in Indian Standard Time


def get_client_ip():
    """Real visitor IP. On Render the app is behind a proxy, so we read X-Forwarded-For."""
    forwarded = request.headers.get("X-Forwarded-For", "")
    ip = forwarded.split(",")[0].strip() if forwarded else request.remote_addr
    return (ip or "unknown")[:45]


def insert_event(cur, ip, activity, endpoint, score):
    cur.execute(
        """INSERT INTO security_events (ip_address, activity, endpoint, risk_score, risk_level)
           VALUES (%s, %s, %s, %s, %s)""",
        (ip, activity, endpoint, score, get_risk_level(score)),
    )
    return {"ip": ip, "activity": activity, "endpoint": endpoint,
            "risk_score": score, "risk_level": get_risk_level(score)}


def format_event(row):
    when = row["timestamp"].astimezone(IST)
    return {
        "id": row["id"],
        "date": when.strftime("%d-%m-%Y"),
        "time": when.strftime("%H:%M:%S"),
        "ip": row["ip_address"],
        "activity": row["activity"],
        "endpoint": row["endpoint"],
        "risk_score": row["risk_score"],
        "risk_level": row["risk_level"],
    }


def login_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if not session.get("admin"):
            if request.path.startswith(("/api/", "/simulate/")):
                return jsonify(error="Not logged in"), 401
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapper


# =====================================================================
#  MONITORING FUNCTIONS (each one saves an event in the cloud database)
# =====================================================================

def record_successful_login(ip):
    with db() as cur:
        return insert_event(cur, ip, "Successful login", "/", NORMAL_SCORE)


def record_failed_login(ip, simulated=False):
    prefix = "Simulated: " if simulated else ""
    with db() as cur:
        # How many failed logins did this IP make in the last 10 minutes?
        cur.execute(
            """SELECT COUNT(*) AS n FROM security_events
               WHERE ip_address = %s AND activity ILIKE %s
               AND timestamp > NOW() - %s * INTERVAL '1 minute'""",
            (ip, "%failed login%", WINDOW_MINUTES),
        )
        attempts = cur.fetchone()["n"] + 1   # +1 for the attempt happening now

        # ---- simple rule ----
        if attempts >= CRITICAL_FAILED_AFTER:
            score = CRITICAL_SCORE
            activity = f"{prefix}Repeated suspicious activity: {attempts} failed logins"
        elif attempts >= REPEATED_FAILED_AFTER:
            score = REPEATED_FAILED_SCORE
            activity = f"{prefix}Repeated failed login ({attempts} attempts)"
        else:
            score = FAILED_LOGIN_SCORE
            activity = f"{prefix}Failed login"
        return insert_event(cur, ip, activity, "/", score)


def record_honeypot(ip, endpoint, method, simulated=False):
    prefix = "Simulated: " if simulated else ""
    action = "attempt" if method == "POST" else "access"
    with db() as cur:
        # How many honeypot hits did this IP make in the last 10 minutes?
        cur.execute(
            """SELECT COUNT(*) AS n FROM security_events
               WHERE ip_address = %s AND endpoint LIKE %s
               AND timestamp > NOW() - %s * INTERVAL '1 minute'""",
            (ip, "/honeypot/%", WINDOW_MINUTES),
        )
        hits = cur.fetchone()["n"] + 1

        # ---- simple rule ----
        activity = f"{prefix}{HONEYPOT_NAMES[endpoint]} {action} ({method})"
        score = HONEYPOT_SCORES[endpoint]
        if hits >= REPEATED_HONEYPOT_AFTER:
            score = CRITICAL_SCORE
            activity = f"{prefix}Repeated suspicious activity: {HONEYPOT_NAMES[endpoint]} {action}"
        return insert_event(cur, ip, activity, endpoint, score)


def get_stats(cur):
    """All dashboard numbers come from ONE query on the cloud database."""
    cur.execute(
        """SELECT
             COUNT(*)                                          AS total,
             COUNT(*) FILTER (WHERE activity ILIKE %(failed)s)   AS failed_logins,
             COUNT(*) FILTER (WHERE endpoint LIKE %(honeypot)s)  AS honeypot_hits,
             COUNT(*) FILTER (WHERE risk_level IN ('High','Critical')) AS high_risk,
             COUNT(*) FILTER (WHERE risk_level = 'Low')        AS low,
             COUNT(*) FILTER (WHERE risk_level = 'Medium')     AS medium,
             COUNT(*) FILTER (WHERE risk_level = 'High')       AS high,
             COUNT(*) FILTER (WHERE risk_level = 'Critical')   AS critical
           FROM security_events""",
        {"failed": "%failed login%", "honeypot": "/honeypot/%"},
    )
    return dict(cur.fetchone())


# =====================================================================
#  ADMIN PAGES
# =====================================================================

@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "GET" and session.get("admin"):
        return redirect(url_for("dashboard"))

    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        ip = get_client_ip()
        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            record_successful_login(ip)
            session["admin"] = True
            return redirect(url_for("dashboard"))
        record_failed_login(ip)           # passwords are never stored
        error = "Invalid username or password."
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html")


@app.route("/reports")
@login_required
def reports():
    with db() as cur:
        stats = get_stats(cur)
        cur.execute(
            """SELECT endpoint, COUNT(*) AS hits FROM security_events
               WHERE endpoint LIKE %s GROUP BY endpoint
               ORDER BY hits DESC, endpoint LIMIT 1""", ("/honeypot/%",))
        top_endpoint = cur.fetchone()
        cur.execute(
            """SELECT ip_address, COUNT(*) AS hits FROM security_events
               GROUP BY ip_address ORDER BY hits DESC, ip_address LIMIT 1""")
        top_ip = cur.fetchone()
    return render_template("reports.html", stats=stats,
                           top_endpoint=top_endpoint, top_ip=top_ip)


@app.route("/api/dashboard")
@login_required
def api_dashboard():
    """The dashboard JavaScript calls this every 5 seconds."""
    columns = "id, timestamp, ip_address, activity, endpoint, risk_score, risk_level"
    with db() as cur:
        stats = get_stats(cur)
        cur.execute(f"SELECT {columns} FROM security_events ORDER BY id DESC LIMIT 15")
        events = [format_event(r) for r in cur.fetchall()]
        cur.execute(f"SELECT {columns} FROM security_events "
                    "WHERE risk_level IN ('High','Critical') ORDER BY id DESC LIMIT 3")
        alerts = [format_event(r) for r in cur.fetchall()]
    return jsonify(stats=stats, events=events, alerts=alerts)


# =====================================================================
#  DEMO BUTTONS (only insert demo rows - no real attacks)
# =====================================================================

@app.route("/simulate/<kind>", methods=["POST"])
@login_required
def simulate(kind):
    if kind == "failed-login":
        event = record_failed_login("192.168.1.10", simulated=True)
    elif kind == "honeypot":
        endpoint = random.choice(list(HONEYPOT_SCORES))
        event = record_honeypot("10.0.0.5", endpoint, "GET", simulated=True)
    elif kind == "critical":
        with db() as cur:
            event = insert_event(cur, "172.16.0.99",
                                 "Simulated: Repeated suspicious activity",
                                 "/honeypot/admin", CRITICAL_SCORE)
    else:
        return jsonify(error="Unknown demo action"), 404
    return jsonify(ok=True, event=event)


# =====================================================================
#  HONEYPOT (fake pages - they show nothing real, they only log visitors)
# =====================================================================

@app.route("/honeypot/login", methods=["GET", "POST"])
def honeypot_login():
    record_honeypot(get_client_ip(), "/honeypot/login", request.method)
    message = "Invalid username or password." if request.method == "POST" else None
    return render_template("honeypot_login.html", message=message)


@app.route("/honeypot/admin", methods=["GET", "POST"])
def honeypot_admin():
    record_honeypot(get_client_ip(), "/honeypot/admin", request.method)
    return render_template("honeypot_admin.html")


@app.route("/honeypot/api", methods=["GET", "POST"])
def honeypot_api():
    record_honeypot(get_client_ip(), "/honeypot/api", request.method)
    return render_template("honeypot_api.html")


if __name__ == "__main__":
    app.run(debug=True, port=int(os.environ.get("PORT", 5000)))
