"""
TelecomNotSecure - VULNERABLE version (Part B)
Intentionally insecure for educational/demonstration purposes only.

Vulnerabilities present:
  Part B.1 - Stored XSS  : system screen renders customer names without HTML escaping
  Part B.2 - SQL Injection: register, login, and system use raw string-concatenated SQL

DO NOT deploy in production.
"""
import hashlib
import hmac as _hmac
import json
import os
import secrets
import smtplib
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage

from dotenv import load_dotenv
from flask import Flask, flash, redirect, render_template, request, session, url_for
from flask_sqlalchemy import SQLAlchemy
from markupsafe import Markup
from sqlalchemy import text

load_dotenv()

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev-secret")
database_url = os.getenv("DATABASE_URL", "sqlite:///telecom_not_secure.db")
if database_url.startswith("postgresql://"):
    database_url = database_url.replace("postgresql://", "postgresql+psycopg://", 1)
app.config["SQLALCHEMY_DATABASE_URI"] = database_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    salt = db.Column(db.String(64), nullable=False)
    password_hmac = db.Column(db.String(128), nullable=False)
    reset_token_sha1 = db.Column(db.String(40), nullable=True)
    failed_attempts = db.Column(db.Integer, nullable=False, default=0)
    locked_until = db.Column(db.DateTime(timezone=True), nullable=True)


class PasswordHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    salt = db.Column(db.String(64), nullable=False)
    password_hmac = db.Column(db.String(128), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))


class Customer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(500), nullable=False)
    last_name = db.Column(db.String(500), nullable=False)
    id_number = db.Column(db.String(100), nullable=False)


# ---------------------------------------------------------------------------
# Password policy helpers (same as secure version – Part A requirements)
# ---------------------------------------------------------------------------

def load_policy():
    with open("password_policy.json", "r", encoding="utf-8") as f:
        return json.load(f)


_DICT_CACHE = {"path": None, "mtime": None, "words": frozenset()}


def load_dictionary(path: str):
    if not path or not os.path.exists(path):
        return frozenset()
    try:
        mtime = os.path.getmtime(path)
    except OSError:
        mtime = None
    if _DICT_CACHE["path"] == path and _DICT_CACHE["mtime"] == mtime:
        return _DICT_CACHE["words"]
    with open(path, "r", encoding="utf-8") as f:
        words = frozenset(line.strip().lower() for line in f if line.strip())
    _DICT_CACHE.update({"path": path, "mtime": mtime, "words": words})
    return words


def validate_password(password: str, user=None):
    policy = load_policy()
    if len(password) < policy["min_length"]:
        return False, f"Password must be at least {policy['min_length']} chars."
    if policy["require_uppercase"] and not any(c.isupper() for c in password):
        return False, "Password must include uppercase letter."
    if policy["require_lowercase"] and not any(c.islower() for c in password):
        return False, "Password must include lowercase letter."
    if policy["require_digit"] and not any(c.isdigit() for c in password):
        return False, "Password must include a digit."
    if policy["require_special"] and not any(c in policy["special_chars"] for c in password):
        return False, "Password must include special char."
    dictionary = load_dictionary(policy.get("dictionary_file", ""))
    if dictionary:
        lowered = password.lower()
        if lowered in dictionary:
            return False, "Password is too common (found in dictionary)."
        for word in dictionary:
            if len(word) >= 5 and word in lowered:
                return False, f"Password contains a common word ('{word}')."
    if user is not None:
        history_size = int(policy.get("history_size", 0))
        if history_size > 0:
            recent = (
                PasswordHistory.query.filter_by(user_id=user.id)
                .order_by(PasswordHistory.created_at.desc())
                .limit(history_size)
                .all()
            )
            for entry in recent:
                if password_to_hmac(password, entry.salt) == entry.password_hmac:
                    return False, f"Password must not match any of the last {history_size} passwords."
    return True, "OK"


def policy_bullets():
    policy = load_policy()
    rules = [f"At least {policy['min_length']} characters"]
    if policy.get("require_uppercase"):
        rules.append("At least one uppercase letter (A-Z)")
    if policy.get("require_lowercase"):
        rules.append("At least one lowercase letter (a-z)")
    if policy.get("require_digit"):
        rules.append("At least one digit (0-9)")
    if policy.get("require_special"):
        rules.append(f"At least one special character ({policy['special_chars']})")
    if policy.get("dictionary_file"):
        rules.append("Must not be a common/dictionary password")
    history_size = int(policy.get("history_size", 0))
    if history_size > 0:
        rules.append(f"Must not match any of your last {history_size} passwords")
    return rules


def record_password_history(user):
    db.session.add(PasswordHistory(user_id=user.id, salt=user.salt, password_hmac=user.password_hmac))
    policy = load_policy()
    history_size = int(policy.get("history_size", 0))
    if history_size > 0:
        keep_ids = [
            row.id
            for row in PasswordHistory.query.filter_by(user_id=user.id)
            .order_by(PasswordHistory.created_at.desc())
            .limit(history_size)
            .all()
        ]
        if keep_ids:
            PasswordHistory.query.filter(
                PasswordHistory.user_id == user.id,
                PasswordHistory.id.notin_(keep_ids),
            ).delete(synchronize_session=False)


def now_utc():
    return datetime.now(timezone.utc)


def is_locked(user) -> bool:
    if user.locked_until is None:
        return False
    locked_until = user.locked_until
    if locked_until.tzinfo is None:
        locked_until = locked_until.replace(tzinfo=timezone.utc)
    return locked_until > now_utc()


def lock_message(user) -> str:
    locked_until = user.locked_until
    if locked_until.tzinfo is None:
        locked_until = locked_until.replace(tzinfo=timezone.utc)
    minutes = max(1, int((locked_until - now_utc()).total_seconds() // 60) + 1)
    return f"Account locked. Try again in about {minutes} minute(s)."


def register_failed_attempt(user):
    policy = load_policy()
    max_attempts = int(policy.get("max_login_attempts", 0))
    lockout_minutes = int(policy.get("lockout_minutes", 15))
    user.failed_attempts = (user.failed_attempts or 0) + 1
    if max_attempts > 0 and user.failed_attempts >= max_attempts:
        user.locked_until = now_utc() + timedelta(minutes=lockout_minutes)
        user.failed_attempts = 0


def clear_lockout(user):
    user.failed_attempts = 0
    user.locked_until = None


@app.context_processor
def inject_password_rules():
    return {"password_rules": policy_bullets()}


def password_to_hmac(password: str, salt: str) -> str:
    key = os.getenv("HMAC_SECRET", "hmac-dev-secret").encode()
    message = (salt + password).encode()
    return _hmac.new(key, message, hashlib.sha256).hexdigest()


def send_mail(to_email: str, subject: str, body: str):
    smtp_host = os.getenv("SMTP_HOST", "")
    smtp_port = int(os.getenv("SMTP_PORT", "587"))
    smtp_user = os.getenv("SMTP_USER", "")
    smtp_pass = os.getenv("SMTP_PASS", "")
    mail_from = os.getenv("MAIL_FROM", "no-reply@communication-ltd.com")
    if not smtp_host:
        print(f"[DEV EMAIL] To: {to_email} | Subject: {subject} | Body: {body}")
        return
    msg = EmailMessage()
    msg["From"] = mail_from
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.set_content(body)
    with smtplib.SMTP(smtp_host, smtp_port) as server:
        server.starttls()
        server.login(smtp_user, smtp_pass)
        server.send_message(msg)


@app.route("/")
def index():
    return redirect(url_for("login"))


# ---------------------------------------------------------------------------
# Part B.2 – SQL INJECTION: /register
#
# Vulnerability: username and email are concatenated directly into SQL strings.
#
# Attack on duplicate check:
#   username = ' OR '1'='1' --
#   → WHERE username = '' OR '1'='1' --' OR email = '...'
#   → Always TRUE → system always reports "user exists", blocking all registrations.
#
# Attack on INSERT:
#   username = legit'), ('evil','evil@x.com','salt','hash',0)--
#   → Inserts a second row with attacker-controlled credentials.
# ---------------------------------------------------------------------------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"].strip()
        email = request.form["email"].strip().lower()
        password = request.form["password"]
        values = {"username": username, "email": email}
        errors = {}

        if not username:
            errors["username"] = "Username is required."
        if not email:
            errors["email"] = "Email is required."

        valid, msg = validate_password(password)
        if not valid:
            errors["password"] = msg

        if errors:
            return render_template("register.html", values=values, errors=errors)

        # SQLI VULNERABLE – raw string concatenation; no parameterization
        existing = db.session.execute(
            text(f"SELECT id FROM user WHERE username = '{username}' OR email = '{email}'")
        ).first()

        if existing:
            errors["username"] = "User or email already exists."
            return render_template("register.html", values=values, errors=errors)

        salt = secrets.token_hex(16)
        hashed = password_to_hmac(password, salt)

        # SQLI VULNERABLE – INSERT with raw string concatenation
        db.session.execute(
            text(
                f"INSERT INTO user (username, email, salt, password_hmac, failed_attempts) "
                f"VALUES ('{username}', '{email}', '{salt}', '{hashed}', 0)"
            )
        )
        db.session.commit()

        new_user = User.query.filter_by(username=username).first()
        if new_user:
            record_password_history(new_user)
            db.session.commit()

        flash("Registration succeeded.")
        return redirect(url_for("login"))
    return render_template("register.html", values={}, errors={})


# ---------------------------------------------------------------------------
# Part B.2 – SQL INJECTION: /login
#
# Vulnerability: username is concatenated directly into the SELECT query.
#
# Attack (information disclosure / bypass):
#   username = ' OR '1'='1' LIMIT 1 --
#   → WHERE username = '' OR '1'='1' LIMIT 1 --'
#   → Returns the first user row regardless of username input.
#
# Attack (data extraction via UNION):
#   username = ' UNION SELECT id, username, email, salt, password_hmac, 0, NULL FROM user --
#   → Extracts all user credentials through the login response.
# ---------------------------------------------------------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]
        values = {"username": username}
        errors = {}

        if not username:
            errors["username"] = "Username is required."
        if not password:
            errors["password"] = "Password is required."
        if errors:
            return render_template("login.html", values=values, errors=errors)

        # SQLI VULNERABLE – raw string concatenation
        row = db.session.execute(
            text(
                f"SELECT id, username, email, salt, password_hmac, failed_attempts, locked_until "
                f"FROM user WHERE username = '{username}'"
            )
        ).mappings().first()

        if not row:
            errors["username"] = "User does not exist."
            return render_template("login.html", values=values, errors=errors)

        user = User.query.get(row["id"])
        if is_locked(user):
            errors["username"] = lock_message(user)
            return render_template("login.html", values=values, errors=errors)

        # SQLi BYPASS: if the SQL returned a different user than was typed,
        # injection occurred → skip the password check and log straight in.
        # Attack: username = ' OR '1'='1' LIMIT 1 --
        # The query ignores the username and returns the first row in the table.
        if row["username"] != username:
            clear_lockout(user)
            db.session.commit()
            session["user_id"] = user.id
            flash("Logged in successfully.")
            return redirect(url_for("system_screen"))

        if password_to_hmac(password, user.salt) != user.password_hmac:
            register_failed_attempt(user)
            db.session.commit()
            if is_locked(user):
                errors["username"] = lock_message(user)
            else:
                policy = load_policy()
                max_attempts = int(policy.get("max_login_attempts", 0))
                remaining = max(0, max_attempts - (user.failed_attempts or 0)) if max_attempts > 0 else None
                if remaining is not None:
                    errors["password"] = f"Wrong password. {remaining} attempt(s) left before lockout."
                else:
                    errors["password"] = "Wrong password."
            return render_template("login.html", values=values, errors=errors)

        clear_lockout(user)
        db.session.commit()
        session["user_id"] = user.id
        flash("Logged in successfully.")
        return redirect(url_for("system_screen"))
    return render_template("login.html", values={}, errors={})


@app.route("/change-password", methods=["GET", "POST"])
def change_password():
    user_id = session.get("user_id")
    if not user_id:
        flash("Please login first.")
        return redirect(url_for("login"))
    user = User.query.get(user_id)
    reset_flow = bool(session.get("password_reset_pending"))
    if request.method == "POST":
        old_password = "" if reset_flow else request.form.get("old_password", "")
        new_password = request.form["new_password"]
        errors = {}

        if not reset_flow and not old_password:
            errors["old_password"] = "Current password is required."
        if not new_password:
            errors["new_password"] = "New password is required."
        if errors:
            return render_template("change_password.html", reset_flow=reset_flow, errors=errors)

        if not reset_flow and password_to_hmac(old_password, user.salt) != user.password_hmac:
            errors["old_password"] = "Current password is wrong."
            return render_template("change_password.html", reset_flow=reset_flow, errors=errors)
        valid, msg = validate_password(new_password, user=user)
        if not valid:
            errors["new_password"] = msg
            return render_template("change_password.html", reset_flow=reset_flow, errors=errors)
        user.salt = secrets.token_hex(16)
        user.password_hmac = password_to_hmac(new_password, user.salt)
        record_password_history(user)
        clear_lockout(user)
        db.session.commit()
        session.pop("password_reset_pending", None)
        flash("Password changed successfully.")
        return redirect(url_for("system_screen"))
    return render_template("change_password.html", reset_flow=reset_flow, errors={})


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        username = request.form["username"].strip()
        values = {"username": username}
        errors = {}
        if not username:
            errors["username"] = "Username is required."
            return render_template("forgot_password.html", values=values, errors=errors)
        user = User.query.filter_by(username=username).first()
        if not user:
            errors["username"] = "User not found."
            return render_template("forgot_password.html", values=values, errors=errors)
        random_bytes = secrets.token_bytes(32)
        token_sha1 = hashlib.sha1(random_bytes).hexdigest()
        user.reset_token_sha1 = token_sha1
        db.session.commit()
        send_mail(user.email, "Communication_LTD reset code", f"Your SHA-1 reset value: {token_sha1}")
        flash("Reset value sent to your email.")
        return redirect(url_for("verify_reset"))
    return render_template("forgot_password.html", values={}, errors={})


@app.route("/verify-reset", methods=["GET", "POST"])
def verify_reset():
    if request.method == "POST":
        username = request.form["username"].strip()
        reset_value = request.form["reset_value"].strip()
        values = {"username": username, "reset_value": reset_value}
        errors = {}
        if not username:
            errors["username"] = "Username is required."
        if not reset_value:
            errors["reset_value"] = "SHA-1 value is required."
        if errors:
            return render_template("verify_reset.html", values=values, errors=errors)
        user = User.query.filter_by(username=username).first()
        if not user or user.reset_token_sha1 != reset_value:
            errors["reset_value"] = "Invalid value."
            return render_template("verify_reset.html", values=values, errors=errors)
        session["user_id"] = user.id
        session["password_reset_pending"] = True
        user.reset_token_sha1 = None
        clear_lockout(user)
        db.session.commit()
        flash("Verified. You can now set a new password.")
        return redirect(url_for("change_password"))
    return render_template("verify_reset.html", values={}, errors={})


# ---------------------------------------------------------------------------
# Part B.1 – STORED XSS + Part B.2 – SQL INJECTION: /system
#
# XSS vulnerability:
#   first_name and last_name are stored as-is (no sanitization) and rendered
#   without HTML escaping via Markup() / | safe in the template.
#   Attack: first_name = <script>alert('XSS')</script>
#   Effect: script executes for every user who views the customer list.
#
# SQLi vulnerabilities:
#   1. Duplicate check: id_number concatenated into WHERE clause.
#      Attack: id_number = ' OR '1'='1' --  → always finds a duplicate, blocks all adds.
#
#   2. INSERT: first_name / last_name / id_number concatenated into VALUES.
#      Attack: last_name = x', '123'); DROP TABLE customer; --
#
#   3. Search: search term concatenated into WHERE LIKE clause.
#      Attack: search = ' UNION SELECT id, username, email, id FROM user --
#      Effect: dumps user credentials into the customer results table.
# ---------------------------------------------------------------------------
@app.route("/system", methods=["GET", "POST"])
def system_screen():
    if not session.get("user_id"):
        flash("Please login first.")
        return redirect(url_for("login"))

    new_customer_name = None
    errors = {}
    values = {}

    if request.method == "POST":
        # No .strip() on name fields – preserves HTML/JS for XSS demo
        first_name = request.form.get("first_name", "")
        last_name = request.form.get("last_name", "")
        id_number = request.form.get("id_number", "").strip()
        values = {"first_name": first_name, "last_name": last_name, "id_number": id_number}

        if not first_name:
            errors["first_name"] = "First name is required."
        if not last_name:
            errors["last_name"] = "Last name is required."
        if not id_number:
            errors["id_number"] = "ID number is required."

        if not errors:
            # SQLI VULNERABLE – id_number injected into WHERE clause
            dup = db.session.execute(
                text(f"SELECT id FROM customer WHERE id_number = '{id_number}'")
            ).first()

            if dup:
                errors["id_number"] = "ID number already exists."
            else:
                # SQLI VULNERABLE – all three fields injected into INSERT VALUES
                # XSS  VULNERABLE – first_name / last_name stored without sanitization
                #
                # Note: single quotes in name fields are doubled ('')  so the raw SQL
                # does not break — this is the naive "fix" many developers apply.
                # It prevents a SQL syntax error but DOES NOT prevent XSS because
                # the content is still rendered raw via | safe in the template.
                # The id_number field is left completely unescaped for the duplicate-
                # check injection demo.
                fn_sql = first_name.replace("'", "''")
                ln_sql = last_name.replace("'", "''")
                db.session.execute(
                    text(
                        f"INSERT INTO customer (first_name, last_name, id_number) "
                        f"VALUES ('{fn_sql}', '{ln_sql}', '{id_number}')"
                    )
                )
                db.session.commit()
                # Markup() marks the string as safe → Jinja2 will NOT auto-escape it (XSS)
                new_customer_name = Markup(first_name + " " + last_name)

    # Search feature – also SQLI VULNERABLE (UNION-based data extraction)
    search = request.args.get("search", "").strip()
    if search:
        # SQLI VULNERABLE – search term injected into LIKE clause
        # Attack: ' UNION SELECT id, username, email, id FROM user --
        customers = db.session.execute(
            text(
                f"SELECT id, first_name, last_name, id_number FROM customer "
                f"WHERE first_name LIKE '%{search}%' OR last_name LIKE '%{search}%'"
            )
        ).mappings().all()
    else:
        customers = db.session.execute(
            text("SELECT id, first_name, last_name, id_number FROM customer ORDER BY id DESC")
        ).mappings().all()

    return render_template(
        "system.html",
        new_customer_name=new_customer_name,
        values=values,
        errors=errors,
        customers=customers,
        search=search,
    )


@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out.")
    return redirect(url_for("login"))


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True, port=5001)
