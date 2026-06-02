# Communication_LTD — Web Security Project

A Flask web application for a fictional telecom company, submitted as part of a Cyber Security course.

The project contains **two versions** of the same application:

| Folder | Description |
|---|---|
| `TelecomSecure/` | The secure version (Part A) |
| `TelecomNotSecure/` | The vulnerable version that demonstrates SQL Injection and Stored XSS (Part B) |

---

## Requirements

- Python 3.10 or newer
- pip (installed with Python)

---

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/adanisiv/ComputerSecurityProject.git
cd ComputerSecurityProject
```

### 2. Create a virtual environment

**Windows:**
```bash
python -m venv venv
venv\Scripts\activate
```

**macOS / Linux:**
```bash
python -m venv venv
source venv/bin/activate
```

The terminal will show `(venv)` when the environment is active.

### 3. Install dependencies

```bash
pip install -r TelecomSecure/requirements.txt
```

### 4. Create the `.env` files

**Windows:**
```bash
copy TelecomSecure\.env.example TelecomSecure\.env
copy TelecomNotSecure\.env.example TelecomNotSecure\.env
```

**macOS / Linux:**
```bash
cp TelecomSecure/.env.example TelecomSecure/.env
cp TelecomNotSecure/.env.example TelecomNotSecure/.env
```

No changes to the `.env` files are needed — the defaults work out of the box.

---

## Running the Application

Both versions can run at the same time — the secure version uses port `5000` and the vulnerable version uses port `5001`.

### Secure version

```bash
cd TelecomSecure
python app.py
```

Open **http://127.0.0.1:5000** in your browser.

### Vulnerable version

In a second terminal:

```bash
cd TelecomNotSecure
python app.py
```

Open **http://127.0.0.1:5001** in your browser.

To stop a server, press **Ctrl + C** in its terminal.

---

## Application Flow

| Route | Purpose |
|---|---|
| `/register` | Create a new account |
| `/login` | Sign in |
| `/system` | Add customers and search the customer list |
| `/change-password` | Change your password (current password required) |
| `/forgot-password` | Request a reset code |
| `/verify-reset` | Enter the reset code to access password change |
| `/logout` | End your session |

### Password reset

After submitting the forgot-password form, a reset code is sent to the email address that was used during registration. Paste the code into the verify-reset page to continue.

---

## Password Policy

All rules are configured in `password_policy.json` in each version's folder. The administrator can modify the policy without changing any code.

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

---

## Part B — Vulnerabilities and Defences

Part B has four requirements. Each one is implemented and demonstrated in the two versions of the project:

| # | Requirement | Where implemented |
|---|---|---|
| **B.1** | Stored XSS attack on Part A section 4 (System screen) | `TelecomNotSecure` |
| **B.2** | SQL Injection on Part A sections 1 (Register), 3 (Login), 4 (System) | `TelecomNotSecure` |
| **B.3** | Defence against XSS using HTML character encoding | `TelecomSecure` |
| **B.4** | Defence against SQL Injection using parameterised queries | `TelecomSecure` |

> **Before testing:** make sure at least one user is registered in the vulnerable version (e.g. username `demo`, any valid email, a password that meets the policy). The SQL Injection on Login needs at least one row in the `user` table to return.

---

### B.1 — Stored XSS attack (vulnerable version)

**Location:** System screen — Add Customer form (`TelecomNotSecure`, port 5001)

**Why it is vulnerable:** `templates/system.html` renders customer names with the `| safe` Jinja2 filter, which disables HTML escaping.

**Steps:**
1. Log in to `http://127.0.0.1:5001`
2. Open the **System** screen
3. In the **First name** field, paste:
   ```html
   <script>alert('XSS Attack!')</script>
   ```
4. Fill **Last name** with anything (e.g. `Test`) and **ID number** with anything (e.g. `12345678`)
5. Click **Add customer**

The browser executes the script immediately, and again every time any logged-in user views the customer list (stored XSS).

---

### B.2 — SQL Injection attacks (vulnerable version)

All three attacks work on `TelecomNotSecure` (port 5001). Each route builds SQL with raw f-string concatenation, so the user input becomes part of the query itself.

#### B.2.a — SQLi on Register (Part A section 1)

**Goal:** Block every future registration by making the duplicate-check always return TRUE.

**Steps:**
1. Open `/register`
2. Fill the form with:
   ```
   Username:  ' OR '1'='1' --
   Email:     any@example.com
   Password:  Aa1!aaaaaa  (any password that meets the policy)
   ```
3. Submit

The app responds **"User or email already exists"** — and every future register attempt will fail the same way, because the WHERE clause is always TRUE.

#### B.2.b — SQLi on Login (Part A section 3)

**Goal:** Log in without knowing any password.

**Steps:**
1. Open `/login`
2. Fill the form with:
   ```
   Username:  ' OR '1'='1' LIMIT 1 --
   Password:  anything
   ```
3. Submit

You are logged in as the first user in the database. The password is never checked.

#### B.2.c — SQLi on System (Part A section 4)

**Goal:** Extract data from another table (`user`) through the customer search.

**Steps:**
1. Log in (use B.2.b if you don't know a password)
2. Open the **System** screen
3. In the **search box**, paste:
   ```sql
   ' UNION SELECT id, username, email, id FROM user --
   ```
4. Press **Search**

The customer list now also shows every row from the `user` table (usernames and emails leaked).

---

### B.3 — Defence against XSS (secure version)

**Location:** System screen in `TelecomSecure` (port 5000)

**Defence used:** HTML character encoding (Jinja2's built-in auto-escaping). All user-provided content is rendered with plain `{{ ... }}` — no `| safe` filter. Characters like `<`, `>`, `'`, `"`, `&` are converted to HTML entities before reaching the page.

**Verify:** repeat the steps from B.1 on `http://127.0.0.1:5000`. The customer is added, and its name is displayed as the literal text `<script>alert('XSS Attack!')</script>` instead of being executed.

---

### B.4 — Defence against SQL Injection (secure version)

**Location:** Register, Login, and System screens in `TelecomSecure` (port 5000)

**Defence used:** parameterised queries through SQLAlchemy's ORM (`User.query.filter_by(...)`, `Customer.query.filter(...)`). User input is sent to the database as a bound parameter, never as part of the SQL text — so it can never change the structure of the query. Strict server-side input validation (regex on usernames, emails, names) adds a second layer of protection.

**Verify:** repeat the attacks from B.2.a, B.2.b and B.2.c on `http://127.0.0.1:5000`:
- **Register:** the username `' OR '1'='1' --` is rejected by input validation ("letters, numbers, and underscore only").
- **Login:** the same payload simply returns "User does not exist" — the quotes are stored as part of the literal username and never break the query.
- **System search:** the UNION payload returns "No customers match …" — the entire string is matched literally against `first_name`/`last_name`.

---

## Project Structure

```
ComputerSecurityProject/
│
├── TelecomSecure/                  Secure version (Part A)
│   ├── app.py                      Main Flask application
│   ├── password_policy.json        Password rules
│   ├── common_passwords.txt        Dictionary of weak passwords
│   ├── requirements.txt
│   ├── .env.example                Template for environment variables
│   └── templates/                  HTML templates
│
└── TelecomNotSecure/               Vulnerable version (Part B)
    ├── app.py
    ├── password_policy.json
    ├── common_passwords.txt
    ├── requirements.txt
    ├── .env.example
    └── templates/
```
