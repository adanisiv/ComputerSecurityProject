# Communication_LTD — Web Security Project

A Flask web application for a fictional telecom company, built as a Cyber Security course final project.

**Repository:** https://github.com/adanisiv/ComputerSecurityProject

The project has **two separate versions** of the same app:

| Folder | What it is |
|---|---|
| `TelecomSecure/` | **Part A** — the secure, properly built version |
| `TelecomNotSecure/` | **Part B** — an intentionally vulnerable version that demonstrates real attacks |

---

## Setup

### Step 1 — Clone the repository

```bash
git clone https://github.com/adanisiv/ComputerSecurityProject.git
cd ComputerSecurityProject
```

### Step 2 — Create a virtual environment

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

You will see `(venv)` in your terminal when the environment is active.

### Step 3 — Install dependencies

```bash
pip install -r TelecomSecure/requirements.txt
```

### Step 4 — Create the config files

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

### Step 5 — Run the apps

Both versions can run at the same time. Open **two terminals**:

**Terminal 1 — Secure version:**
```bash
cd TelecomSecure
python app.py
```
Open `http://127.0.0.1:5000` in your browser.

**Terminal 2 — Vulnerable version:**
```bash
cd TelecomNotSecure
python app.py
```
Open `http://127.0.0.1:5001` in your browser.

To stop either server press **Ctrl + C** in its terminal.

---

## How to use the app

1. Go to `/register` and create an account
2. Log in at `/login`
3. You will land on the **System screen** where you can add, search, and delete customers
4. To change your password go to `/change-password`
5. If you forget your password, use `/forgot-password` — a reset code will be sent to your email

### Password requirements

Passwords must follow the rules in `password_policy.json`:
- Minimum 10 characters
- At least one uppercase letter, one lowercase letter, one digit, one special character
- Cannot be a common/dictionary password
- Cannot reuse any of your last 3 passwords
- Account is locked for 15 minutes after 3 failed login attempts

---

## Part B — Security Attacks and Defences

> **Before you start:** open the **vulnerable version** at `http://127.0.0.1:5001` and register one normal user first (e.g. username `demo`, any email, a valid password like `Demo1!demo`). Several attacks below require at least one user to exist in the database.

---

### B.1 — Stored XSS Attack

**What is XSS?** The app stores whatever you type into the database and then displays it on the page without checking it. If you type HTML or JavaScript instead of a name, the browser will run it as code.

**Where:** System screen → Add Customer form (vulnerable version only)

**Steps:**
1. Log in at `http://127.0.0.1:5001`
2. Go to the **System** screen
3. Fill in the Add Customer form:
   - First name: `<script>alert('XSS')</script>`
   - Last name: `Test`
   - ID number: `12345678`
4. Click **Add customer**

**What happens:** a popup appears saying "XSS". The script is now saved in the database. Every time **any** user opens the System screen the popup fires again — that is what makes it *Stored* XSS (the attack persists for everyone, not just the person who submitted it).

**Defence (secure version):** repeat the same steps on `http://127.0.0.1:5000`. The customer is added normally but the name is displayed as plain text — `<script>alert('XSS')</script>` — the browser never executes it. The secure version uses Jinja2's built-in HTML encoding which converts `<` to `&lt;` and `>` to `&gt;`, so the browser treats it as text, not code.

> **To stop the popup:** go to the System screen, find the customer with the script as its name, and click the **✕** button to delete it.

---

### B.2 — SQL Injection Attacks

**What is SQL Injection?** The app builds its database queries by pasting the user's input directly into the SQL string. An attacker can type a carefully crafted input that changes the meaning of the query — bypassing security checks or leaking data.

---

#### Attack 1 — Block all future registrations

**Where:** `/register` — username field (vulnerable version)

**Steps:**
1. Go to `http://127.0.0.1:5001/register`
2. Fill in:
   - Username: `' OR '1'='1' --`
   - Email: `any@test.com`
   - Password: `Demo1!demo`
3. Click **Create account**

**What happens:** the app says "User or email already exists." Nobody can ever register again — the username turns the duplicate-check query into one that is always TRUE, so the system always thinks the user already exists.

**Defence (secure version):** try the same on `http://127.0.0.1:5000/register`. The username field rejects it immediately: *"Username must be 3–20 characters: letters, numbers, and underscore only."* The input never even reaches the database.

---

#### Attack 2 — Log in without a password

**Where:** `/login` — username field (vulnerable version)

**Steps:**
1. Go to `http://127.0.0.1:5001/login`
2. Fill in:
   - Username: `' OR '1'='1' LIMIT 1 --`
   - Password: `anything`
3. Click **Sign in**

**What happens:** you are logged in as the first user in the database — no password needed. The username payload makes the query return the first row in the user table regardless of what was typed, completely bypassing authentication.

**Defence (secure version):** try the same on `http://127.0.0.1:5000/login`. The app responds "User does not exist." The input is passed as a safe parameter, so the database looks for a user literally named `' OR '1'='1' LIMIT 1 --` and finds nothing.

---

#### Attack 3 — Steal all user data through search

**Where:** `/system` — search box (vulnerable version)

**Steps:**
1. Log in (use Attack 2 if needed)
2. Go to the **System** screen at `http://127.0.0.1:5001/system`
3. Use the following payloads in the **search box** (execute them one by one):

**List all tables in the database:**

' UNION SELECT 1, name, 2, 3 FROM sqlite_master WHERE type='table' --

**List all columns in the user table:**

' UNION SELECT 1, name, type, 3 FROM pragma_table_info('user') --

**Dump all usernames and emails:**

```
' UNION SELECT id, username, email, id FROM user --
```

**Dump usernames and hashed passwords (proves DB breach):**

```
' UNION SELECT id, username, password_hmac, id FROM user --
```

4. Click **Search**

**What happens:** the customer list exposes every registered user's data directly from the database. The first payload shows usernames and emails. The second payload shows the stored password hashes — proving the attacker has fully breached the database and stolen the credentials.

Even though the passwords appear as unreadable hashes (e.g. `9a3f7c2b1d4e...`), this is still a critical breach — an attacker can take these hashes offline and attempt to crack them.

This is exactly what HMAC-SHA256 with a unique salt (used in the secure version) is designed to prevent: even if hashes are stolen, cracking them becomes computationally infeasible.

**Defence (secure version):** try the same on `http://127.0.0.1:5000/system`. The result is simply "No customers match…" — the entire search string is treated as a literal name to search for, not as SQL code.

---

## Project Structure

```
ComputerSecurityProject/
│
├── TelecomSecure/          Secure version (Part A)
│   ├── app.py              Main application
│   ├── password_policy.json
│   ├── common_passwords.txt
│   ├── requirements.txt
│   ├── .env.example
│   └── templates/
│
└── TelecomNotSecure/       Vulnerable version (Part B)
    ├── app.py
    ├── password_policy.json
    ├── common_passwords.txt
    ├── requirements.txt
    ├── .env.example
    └── templates/
```
