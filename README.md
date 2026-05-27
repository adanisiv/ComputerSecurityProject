# Communication_LTD — Web Security Project

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-3.x-black?logo=flask)
![SQLite](https://img.shields.io/badge/Database-SQLite-lightgrey?logo=sqlite)
![Status](https://img.shields.io/badge/Status-Complete-brightgreen)

A full-stack web application for a fictional telecom company, built as part of a **Cyber Security course**.
The project demonstrates **secure development principles** (Part A) alongside real-world **web attack techniques** (Part B), delivered as two separate versions of the same application.

---

## Table of Contents

- [Overview](#overview)
- [Project Structure](#project-structure)
- [Features](#features)
- [Quick Start](#quick-start)
- [Running the App](#running-the-app)
- [How to Use](#how-to-use)
- [Password Policy](#password-policy)
- [Security Vulnerabilities — Part B](#security-vulnerabilities--part-b)
- [Tech Stack](#tech-stack)
- [Security Notes](#security-notes)

---

## Overview

This project builds a web portal for **Communication_LTD**, a fictional internet service provider. Employees can register, log in, manage their account, and add customers to the system.

The project is submitted as two versions:

| Version | Folder | Description |
|---|---|---|
| **Secure** | `TelecomSecure/` | All security controls in place |
| **Vulnerable** | `TelecomNotSecure/` | Intentionally insecure — demonstrates SQLi and XSS attacks |

---

## Project Structure

```
ComputerSecurityProject/
│
├── TelecomSecure/                  Secure version (Part A + Part B fixes)
│   ├── app.py                      Main Flask application
│   ├── password_policy.json        Password rules — editable by admin
│   ├── common_passwords.txt        Dictionary of weak passwords to block
│   ├── requirements.txt
│   ├── .env.example                Template for environment variables
│   └── templates/
│       ├── base.html
│       ├── login.html
│       ├── register.html
│       ├── change_password.html
│       ├── forgot_password.html
│       ├── verify_reset.html
│       └── system.html
│
└── TelecomNotSecure/               Vulnerable version (Part B demonstrations)
    ├── app.py                      Same app with intentional SQLi and XSS flaws
    ├── password_policy.json
    ├── common_passwords.txt
    ├── requirements.txt
    ├── .env.example
    └── templates/
        └── ...                     Same pages with XSS-vulnerable rendering
```

---

## Features

### Part A — Secure Development

| # | Feature | Details |
|---|---|---|
| 1 | **Register** | Username, email, and password with full validation |
| 2 | **Password Policy** | Minimum length, uppercase, lowercase, digits, and special characters — configured via `password_policy.json` |
| 3 | **HMAC + Salt Storage** | Passwords stored as HMAC-SHA256 with a unique random salt — never in plain text |
| 4 | **Password History** | Last 3 passwords are remembered — reuse is blocked |
| 5 | **Dictionary Check** | Common and weak passwords are rejected |
| 6 | **Login** | Verifies credentials with clear error messages |
| 7 | **Account Lockout** | Account locks for 15 minutes after 3 failed attempts |
| 8 | **Change Password** | Requires the current password and enforces the full policy |
| 9 | **Forgot Password** | Generates a SHA-1 token, sends it by email, and uses it to unlock the reset flow |
| 10 | **System Screen** | Add and search customers by first name, last name, and ID number |

### Part B — Vulnerability Demonstrations

| # | Vulnerability | Location |
|---|---|---|
| 1 | **Stored XSS** | System screen — customer names rendered without HTML escaping |
| 2 | **SQL Injection** | Register, Login, and System screen — raw string-concatenated queries |
| 3 | **XSS Fix** | Character encoding via Jinja2 auto-escaping in `TelecomSecure` |
| 4 | **SQLi Fix** | Parameterized queries via SQLAlchemy ORM in `TelecomSecure` |

---

## Quick Start

### Prerequisites

- Python 3.10 or newer — [download here](https://www.python.org/downloads/)
- pip (included with Python)
- Git — [download here](https://git-scm.com/)

### Step 1 — Clone the repository

```bash
git clone https://github.com/adanisiv/ComputerSecurityProject.git
cd ComputerSecurityProject
```

### Step 2 — Create a virtual environment

```bash
# Create
python -m venv venv

# Activate on Windows
venv\Scripts\activate

# Activate on macOS / Linux
source venv/bin/activate
```

The terminal prompt will show `(venv)` when the environment is active.

### Step 3 — Install dependencies

```bash
pip install -r TelecomSecure/requirements.txt
```

### Step 4 — Set up environment variables

```bash
# Windows
copy TelecomSecure\.env.example TelecomSecure\.env

# macOS / Linux
cp TelecomSecure/.env.example TelecomSecure/.env
```

Open `TelecomSecure/.env` and fill in the values:

```env
SECRET_KEY=any-random-string-you-choose
HMAC_SECRET=another-random-string-you-choose
DATABASE_URL=sqlite:///telecom_secure.db
```

For local development the SQLite line is sufficient. For production, replace `DATABASE_URL` with a PostgreSQL connection string.

---

## Running the App

### Secure version

```bash
cd TelecomSecure
python app.py
```

Open **http://127.0.0.1:5000** in your browser.

### Vulnerable version

```bash
# Set up its .env first
copy TelecomNotSecure\.env.example TelecomNotSecure\.env   # Windows
cp TelecomNotSecure/.env.example TelecomNotSecure/.env     # macOS / Linux

cd TelecomNotSecure
python app.py
```

Open **http://127.0.0.1:5000** in your browser.

> Run only one version at a time. Both default to port 5000.

---

## How to Use

Once the application is running, follow this flow:

```
1. /register          Create a new account (username, email, strong password)
2. /login             Sign in with your credentials
                      Account locks after 3 wrong attempts
3. /system            Add a new customer (first name, last name, ID number)
                      Search existing customers by name
4. /change-password   Update your password (current password required)
5. /forgot-password   Request a reset code sent to your email
6. /verify-reset      Enter the SHA-1 code to access the password reset page
7. /logout            End your session
```

> **Development mode:** If no SMTP server is configured in `.env`, the password reset code is printed to the terminal instead of being emailed.

---

## Password Policy

All password rules are defined in `password_policy.json`. The administrator can update them without modifying any code.

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

| Setting | Description |
|---|---|
| `min_length` | Minimum number of characters required |
| `require_uppercase` | Must contain at least one uppercase letter (A–Z) |
| `require_lowercase` | Must contain at least one lowercase letter (a–z) |
| `require_digit` | Must contain at least one digit (0–9) |
| `require_special` | Must contain at least one special character |
| `history_size` | Number of previous passwords that cannot be reused |
| `dictionary_file` | Path to the file containing common passwords to block |
| `max_login_attempts` | Number of failed attempts before the account is locked |
| `lockout_minutes` | Duration of the account lockout in minutes |

---

## Security Vulnerabilities — Part B

> All attacks below apply to `TelecomNotSecure` only. The `TelecomSecure` version is protected against each one.

### 1. Stored XSS — Cross-Site Scripting

**Description:** The attacker stores JavaScript code in the database. Every user who visits the page unknowingly executes that script in their browser.

**How to reproduce:**
1. Run `TelecomNotSecure` and log in
2. Navigate to the System screen
3. Enter the following as the First Name field:
   ```
   <script>alert('XSS Attack!')</script>
   ```
4. Submit — the script executes immediately and on every subsequent page load for all users

**Root cause:** The vulnerable version renders names using `| safe`, which disables Jinja2's HTML escaping.

**Fix applied in TelecomSecure:** The `| safe` filter is removed. Jinja2 automatically encodes `<` as `&lt;` and `>` as `&gt;`, so the input is displayed as plain text and never executed.

---

### 2. SQL Injection

**Description:** The attacker enters SQL code into an input field. Because the input is concatenated directly into the database query string, the database executes the injected code.

**Login bypass**

Enter the following in the Login screen:

```
Username:  ' OR '1'='1' LIMIT 1 --
Password:  anything
```

The query becomes:
```sql
SELECT * FROM user WHERE username = '' OR '1'='1' LIMIT 1 --'
```
The condition is always true, so the database returns the first user — bypassing authentication entirely.

---

**Data extraction via UNION — System search**

Enter the following in the Search box on the System screen:

```
' UNION SELECT id, username, email, id FROM user --
```

The entire contents of the `user` table — including usernames and email addresses — are returned and displayed in the customer list.

---

**Block all registrations — Register screen**

Enter the following in the Username field:

```
' OR '1'='1' --
```

The duplicate-check query always returns a result, so the system permanently reports "user already exists" and no new accounts can be created.

---

**Root cause:** The vulnerable version builds queries using f-strings:
```python
f"SELECT * FROM user WHERE username = '{username}'"
```

**Fix applied in TelecomSecure:** All queries use the SQLAlchemy ORM or bound parameters. User input is passed separately from the SQL string and is treated as data, never as executable code.

---

## Tech Stack

| Layer | Technology |
|---|---|
| Language | Python 3.10+ |
| Web framework | Flask, Jinja2 |
| Database | SQLite (development) / PostgreSQL (production) |
| ORM | Flask-SQLAlchemy |
| Password hashing | HMAC-SHA256 with random salt via the `hmac` and `secrets` modules |
| Reset tokens | SHA-1 of a cryptographically random value |
| Frontend | Custom CSS — no external framework |
| Configuration | JSON-based password policy file |

---

## Security Notes

- `.env` files are excluded from version control via `.gitignore` — do not commit secrets
- `TelecomNotSecure` is for educational demonstration only — do not deploy it on a public server
- For production, use PostgreSQL and set strong values for `SECRET_KEY` and `HMAC_SECRET`
- Without SMTP configuration, password reset tokens are printed to the terminal — suitable for local development only
