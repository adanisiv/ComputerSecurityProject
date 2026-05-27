# 🌐 Communication_LTD — Web Security Project

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-3.x-black?logo=flask)
![SQLite](https://img.shields.io/badge/Database-SQLite-lightgrey?logo=sqlite)
![Status](https://img.shields.io/badge/Status-Complete-brightgreen)

> A full-stack web application for a fictional telecom company, built as part of a **Cyber Security course**.  
> The project demonstrates **secure development principles** (Part A) alongside real-world **web attack techniques** (Part B) — with two separate versions of the same app.

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Project Structure](#-project-structure)
- [Features](#-features)
- [Quick Start](#-quick-start)
- [Running the App](#-running-the-app)
- [How to Use](#-how-to-use)
- [Password Policy](#-password-policy-config)
- [Security Vulnerabilities (Part B)](#-security-vulnerabilities-part-b)
- [Tech Stack](#-tech-stack)

---

## 🔍 Overview

This project builds a web portal for **Communication_LTD**, a fictional internet service provider. Employees can register, log in, manage their account, and add customers to the system.

The project is submitted as **two versions**:

| Version | Folder | Description |
|---|---|---|
| ✅ **Secure** | `TelecomSecure/` | All security controls in place — safe to deploy |
| ⚠️ **Vulnerable** | `TelecomNotSecure/` | Intentionally broken — used to demonstrate SQLi & XSS attacks |

---

## 📁 Project Structure

```
ComputerSecurityProject/
│
├── TelecomSecure/                 ← Secure version (Part A + fixes for Part B)
│   ├── app.py                     ← Main Flask application
│   ├── password_policy.json       ← Password rules (editable by admin)
│   ├── common_passwords.txt       ← Dictionary of weak passwords to block
│   ├── requirements.txt
│   ├── .env.example               ← Template for environment variables
│   └── templates/
│       ├── base.html
│       ├── login.html
│       ├── register.html
│       ├── change_password.html
│       ├── forgot_password.html
│       ├── verify_reset.html
│       └── system.html
│
└── TelecomNotSecure/              ← Vulnerable version (Part B demonstrations)
    ├── app.py                     ← Same app — with intentional SQLi & XSS flaws
    ├── password_policy.json
    ├── common_passwords.txt
    ├── requirements.txt
    ├── .env.example
    └── templates/
        └── ...                    ← Same pages — XSS-vulnerable rendering
```

---

## ✨ Features

### Part A — Secure Development

| # | Feature | Details |
|---|---|---|
| 1 | **Register** | Username, email, password with full validation |
| 2 | **Password Policy** | Minimum length, uppercase, lowercase, digits, special characters — all configured via `password_policy.json` |
| 3 | **HMAC + Salt Storage** | Passwords are never stored in plain text — stored as HMAC-SHA256 with a unique random salt |
| 4 | **Password History** | Last 3 passwords remembered — reuse is blocked |
| 5 | **Dictionary Check** | Common/weak passwords are rejected |
| 6 | **Login** | Verifies credentials and shows clear error messages |
| 7 | **Account Lockout** | Locks for 15 minutes after 3 failed login attempts |
| 8 | **Change Password** | Requires current password — enforces full policy |
| 9 | **Forgot Password** | Generates a SHA-1 token, sends it by email, used to unlock the reset flow |
| 10 | **System Screen** | Add and search customers (first name, last name, ID number) |

### Part B — Vulnerability Demonstrations

| # | Vulnerability | Location |
|---|---|---|
| 1 | **Stored XSS** | System screen — customer names rendered without escaping |
| 2 | **SQL Injection** | Register, Login, and System screen — raw string-concatenated queries |
| 3 | **XSS Fix** | Character encoding via Jinja2 auto-escaping (`TelecomSecure`) |
| 4 | **SQLi Fix** | Parameterized queries via SQLAlchemy ORM (`TelecomSecure`) |

---

## ⚡ Quick Start

### Prerequisites

- **Python 3.10** or newer — [download here](https://www.python.org/downloads/)
- **pip** (comes with Python)
- **Git** — [download here](https://git-scm.com/)

### 1. Clone the repository

```bash
git clone https://github.com/adanisiv/ComputerSecurityProject.git
cd ComputerSecurityProject
```

### 2. Create a virtual environment

```bash
# Create it
python -m venv venv

# Activate it — Windows
venv\Scripts\activate

# Activate it — macOS / Linux
source venv/bin/activate
```

> You'll know it's active when you see `(venv)` at the start of your terminal line.

### 3. Install dependencies

```bash
pip install -r TelecomSecure/requirements.txt
```

### 4. Set up environment variables

```bash
# Windows
copy TelecomSecure\.env.example TelecomSecure\.env

# macOS / Linux
cp TelecomSecure/.env.example TelecomSecure/.env
```

Then open `TelecomSecure/.env` and set your values:

```env
SECRET_KEY=any-random-string-you-choose
HMAC_SECRET=another-random-string-you-choose
DATABASE_URL=sqlite:///telecom_secure.db
```

> **For local development**, the SQLite line above is all you need.  
> For production, replace `DATABASE_URL` with a PostgreSQL connection string.

---

## 🚀 Running the App

### Run the Secure version

```bash
cd TelecomSecure
python app.py
```

Open your browser at 👉 **http://127.0.0.1:5000**

---

### Run the Vulnerable version

```bash
# First — set up its .env too
copy TelecomNotSecure\.env.example TelecomNotSecure\.env   # Windows
# cp TelecomNotSecure/.env.example TelecomNotSecure/.env   # macOS/Linux

cd TelecomNotSecure
python app.py
```

Open your browser at 👉 **http://127.0.0.1:5000**

> ⚠️ Run only **one version at a time**, or change the port in `app.py` — both default to port 5000.

---

## 🖥 How to Use

Once the app is running, here is the full flow:

```
1. /register      → Create a new account
                    (username + email + strong password)

2. /login         → Sign in with your credentials
                    (account locks after 3 wrong attempts)

3. /system        → Add a new customer to the system
                    (first name, last name, ID number)
                    Search existing customers by name

4. /change-password → Update your password
                    (must enter current password first)

5. /forgot-password → Request a reset code by email
6. /verify-reset    → Enter the SHA-1 code from your email
                    → Redirects to set a new password

7. /logout        → End your session
```

> **Email in dev mode:** If no SMTP server is configured in `.env`, the reset code is printed directly to the terminal instead of being emailed.

---

## ⚙️ Password Policy Config

All password rules live in `password_policy.json`. The admin can change them without touching any code:

```json
{
  "min_length": 10,
  "require_uppercase": true,
  "require_lowercase": true,
  "require_digit": true,
  "require_special": true,
  "special_chars": "!@#$%^&*()-_=+[]{};:,.?",
  "history_size": 3,
  "dictionary_file": "common_passwords.txt",
  "max_login_attempts": 3,
  "lockout_minutes": 15
}
```

| Setting | Meaning |
|---|---|
| `min_length` | Minimum number of characters |
| `require_uppercase` | Must contain A–Z |
| `require_lowercase` | Must contain a–z |
| `require_digit` | Must contain 0–9 |
| `require_special` | Must contain a symbol |
| `history_size` | How many old passwords are remembered |
| `dictionary_file` | File with common passwords to block |
| `max_login_attempts` | Failed attempts before lockout |
| `lockout_minutes` | How long the account stays locked |

---

## 🔓 Security Vulnerabilities (Part B)

> These attacks only work in `TelecomNotSecure`. The `TelecomSecure` version is protected against all of them.

### 1. Stored XSS — Cross-Site Scripting

**What it is:** The attacker stores JavaScript code in the database. Every user who visits the page runs that script without knowing.

**How to demo it:**
1. Run `TelecomNotSecure` and log in
2. Go to the **System** screen
3. Enter this as the **First Name**:
   ```
   <script>alert('XSS Attack!')</script>
   ```
4. Submit — the script executes immediately and every time anyone loads the page

**Why it works:** The vulnerable version renders names with `| safe` (disables HTML escaping).  
**The fix:** Remove `| safe` — Jinja2 automatically converts `<` to `&lt;` so it displays as text, never runs.

---

### 2. SQL Injection

**What it is:** The attacker types SQL code into an input field. Because the input is pasted directly into the database query, the database executes it.

#### 🔸 Login bypass
In the **Login** screen, enter:
```
Username: ' OR '1'='1' LIMIT 1 --
Password: anything
```
This turns the query into:
```sql
SELECT * FROM user WHERE username = '' OR '1'='1' LIMIT 1 --'
```
Result: logs in as the first user in the database.

#### 🔸 Data extraction via UNION (System search)
In the **Search** box on the System screen, enter:
```
' UNION SELECT id, username, email, id FROM user --
```
Result: all usernames and emails from the `user` table appear in the customer list.

#### 🔸 Block all registrations (Register screen)
In the **Username** field on Register, enter:
```
' OR '1'='1' --
```
Result: the duplicate-check query always returns true → the system always says "user already exists".

**Why it works:** The vulnerable version builds queries by pasting user input directly into the SQL string (`f"SELECT ... WHERE username = '{username}'"`)  
**The fix:** Use SQLAlchemy ORM — input is passed as a bound parameter, never as part of the SQL string.

---

## 🛠 Tech Stack

| Layer | Technology |
|---|---|
| Language | Python 3.10+ |
| Web framework | Flask + Jinja2 |
| Database | SQLite (dev) / PostgreSQL (prod) |
| ORM | Flask-SQLAlchemy |
| Password hashing | HMAC-SHA256 with random salt (`hmac` + `secrets` modules) |
| Reset tokens | SHA-1 of a cryptographically random value |
| Styling | Custom CSS — no external framework |
| Config | JSON-based password policy |

---

## 🔐 Security Notes

- `.env` files are **git-ignored** — never commit secrets to version control
- The `TelecomNotSecure` version is for **educational demonstration only** — never deploy it publicly
- In production, replace the SQLite database with **PostgreSQL** and set a strong `SECRET_KEY` and `HMAC_SECRET`
- If no SMTP is configured, reset tokens are printed to the **terminal** (safe for local development)
