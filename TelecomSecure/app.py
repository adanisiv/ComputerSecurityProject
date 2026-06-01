import hashlib
import hmac
import json
import os
import secrets
import smtplib
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage

from dotenv import load_dotenv
from flask import Flask, flash, redirect, render_template, request, session, url_for
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text

load_dotenv()

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev-secret")
database_url = os.getenv("DATABASE_URL", "sqlite:///telecom_secure.db")
if database_url.startswith("postgresql://"):
    database_url = database_url.replace("postgresql://", "postgresql+psycopg://", 1)
app.config["SQLALCHEMY_DATABASE_URI"] = database_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
if database_url.startswith("postgresql+psycopg://"):
    app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
        "pool_pre_ping": True,
        "pool_recycle": 180,
    }
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
    first_name = db.Column(db.String(80), nullable=False)
    last_name = db.Column(db.String(80), nullable=False)
    id_number = db.Column(db.String(20), unique=True, nullable=False)


def load_policy():
    with open("password_policy.json", "r", encoding="utf-8") as f:
        return json.load(f)


_DICTIONARY_CACHE = {"path": None, "mtime": None, "words": frozenset()}


def load_dictionary(path: str):
    if not path or not os.path.exists(path):
        return frozenset()
    try:
        mtime = os.path.getmtime(path)
    except OSError:
        mtime = None
    if _DICTIONARY_CACHE["path"] == path and _DICTIONARY_CACHE["mtime"] == mtime:
        return _DICTIONARY_CACHE["words"]
    with open(path, "r", encoding="utf-8") as f:
        words = frozenset(line.strip().lower() for line in f if line.strip())
    _DICTIONARY_CACHE.update({"path": path, "mtime": mtime, "words": words})
    return words


def validate_password(password: str, user: "User | None" = None):
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


def record_password_history(user: "User"):
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


def is_locked(user: "User") -> bool:
    if user.locked_until is None:
        return False
    locked_until = user.locked_until
    if locked_until.tzinfo is None:
        locked_until = locked_until.replace(tzinfo=timezone.utc)
    return locked_until > now_utc()


def lock_message(user: "User") -> str:
    locked_until = user.locked_until
    if locked_until.tzinfo is None:
        locked_until = locked_until.replace(tzinfo=timezone.utc)
    minutes = max(1, int((locked_until - now_utc()).total_seconds() // 60) + 1)
    return f"Account locked. Try again in about {minutes} minute(s)."


def register_failed_attempt(user: "User"):
    policy = load_policy()
    max_attempts = int(policy.get("max_login_attempts", 0))
    lockout_minutes = int(policy.get("lockout_minutes", 15))
    user.failed_attempts = (user.failed_attempts or 0) + 1
    if max_attempts > 0 and user.failed_attempts >= max_attempts:
        user.locked_until = now_utc() + timedelta(minutes=lockout_minutes)
        user.failed_attempts = 0


def clear_lockout(user: "User"):
    user.failed_attempts = 0
    user.locked_until = None


@app.context_processor
def inject_password_rules():
    return {"password_rules": policy_bullets()}


def password_to_hmac(password: str, salt: str):
    key = os.getenv("HMAC_SECRET", "hmac-dev-secret").encode()
    message = (salt + password).encode()
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def send_mail(to_email: str, subject: str, body: str):
    smtp_host = os.getenv("SMTP_HOST", "")
    smtp_port = int(os.getenv("SMTP_PORT", "587"))
    smtp_user = os.getenv("SMTP_USER", "")
    smtp_pass = os.getenv("SMTP_PASS", "")
    mail_from = os.getenv("MAIL_FROM", "no-reply@communication-ltd.com")

    if not smtp_host:
        token = body.split("reset value: ")[-1] if "reset value: " in body else body
        print("\n" + "="*60, flush=True)
        print(f"  PASSWORD RESET TOKEN", flush=True)
        print(f"  To      : {to_email}", flush=True)
        print(f"  TOKEN   : {token}", flush=True)
        print("="*60 + "\n", flush=True)
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

        if User.query.filter((User.username == username) | (User.email == email)).first():
            errors["username"] = "User or email already exists."
            return render_template("register.html", values=values, errors=errors)

        salt = secrets.token_hex(16)
        hashed = password_to_hmac(password, salt)
        new_user = User(username=username, email=email, salt=salt, password_hmac=hashed)
        db.session.add(new_user)
        db.session.flush()
        record_password_history(new_user)
        db.session.commit()
        flash("Registration succeeded.")
        return redirect(url_for("login"))
    return render_template("register.html", values={}, errors={})


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

        user = User.query.filter_by(username=username).first()
        if not user:
            errors["username"] = "User does not exist."
            return render_template("login.html", values=values, errors=errors)
        if is_locked(user):
            errors["username"] = lock_message(user)
            return render_template("login.html", values=values, errors=errors)
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
        if not os.getenv("SMTP_HOST", "").strip():
            # No email server configured — show the token directly on screen (dev mode only)
            flash(f"[DEV] No email server configured. Your reset code: {token_sha1}")
        else:
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


@app.route("/system", methods=["GET", "POST"])
def system_screen():
    if not session.get("user_id"):
        flash("Please login first.")
        return redirect(url_for("login"))
    new_customer_name = None
    errors = {}
    values = {}
    if request.method == "POST":
        first_name = request.form["first_name"].strip()
        last_name = request.form["last_name"].strip()
        id_number = request.form["id_number"].strip()
        values = {"first_name": first_name, "last_name": last_name, "id_number": id_number}

        if not first_name:
            errors["first_name"] = "First name is required."
        if not last_name:
            errors["last_name"] = "Last name is required."
        if not id_number:
            errors["id_number"] = "ID number is required."
        elif not id_number.isdigit():
            errors["id_number"] = "ID number must contain digits only."
        elif len(id_number) not in (8, 9):
            errors["id_number"] = "ID number must be 8-9 digits."

        if not errors and Customer.query.filter_by(id_number=id_number).first():
            errors["id_number"] = "ID number already exists."

        if not errors:
            c = Customer(first_name=first_name, last_name=last_name, id_number=id_number)
            db.session.add(c)
            db.session.commit()
            new_customer_name = f"{c.first_name} {c.last_name}"
            values = {}

    search = request.args.get("search", "").strip()
    if search:
        customers = Customer.query.filter(
            (Customer.first_name.ilike(f"%{search}%")) |
            (Customer.last_name.ilike(f"%{search}%"))
        ).order_by(Customer.id.desc()).all()
    else:
        customers = Customer.query.order_by(Customer.id.desc()).all()

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


def migrate_schema():
    is_postgres = database_url.startswith("postgresql+psycopg://")
    stmts = []
    if is_postgres:
        stmts = [
            'ALTER TABLE "user" ADD COLUMN IF NOT EXISTS failed_attempts INTEGER NOT NULL DEFAULT 0',
            'ALTER TABLE "user" ADD COLUMN IF NOT EXISTS locked_until TIMESTAMPTZ',
        ]
    else:
        existing_cols = {row[1] for row in db.session.execute(text("PRAGMA table_info(user)")).fetchall()}
        if "failed_attempts" not in existing_cols:
            stmts.append("ALTER TABLE user ADD COLUMN failed_attempts INTEGER NOT NULL DEFAULT 0")
        if "locked_until" not in existing_cols:
            stmts.append("ALTER TABLE user ADD COLUMN locked_until DATETIME")
    for sql in stmts:
        db.session.execute(text(sql))
    db.session.commit()
    db.create_all()


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        migrate_schema()
    app.run(debug=True)
