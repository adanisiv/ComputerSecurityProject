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

> Run only **one** version at a time. Both use port 5000.

### Secure version

```bash
cd TelecomSecure
python app.py
```

Open **http://127.0.0.1:5000** in your browser.

### Vulnerable version

```bash
cd TelecomNotSecure
python app.py
```

Open **http://127.0.0.1:5000** in your browser.

To stop the server, press **Ctrl + C** in the terminal.

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

### Password reset (development mode)

If no SMTP server is configured in `.env`, the SHA-1 reset code is shown on the screen after submitting the forgot-password form. Copy it directly into the verify-reset page.

To send real emails instead, fill in the SMTP fields in `.env`:

```env
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your.email@gmail.com
SMTP_PASS=your-app-password
MAIL_FROM=your.email@gmail.com
```

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

## Testing the Vulnerabilities (Part B)

The following attacks work **only** in the `TelecomNotSecure` version. The `TelecomSecure` version is protected against each one.

### 1. Stored XSS — System screen

1. Log in to `TelecomNotSecure`
2. Go to the System screen
3. In the **First Name** field, enter:
   ```
   <script>alert('XSS Attack!')</script>
   ```
4. Submit. The script runs immediately and on every page load for any user who views the customer list.

### 2. SQL Injection — Login bypass

On the Login screen, enter:
```
Username:  ' OR '1'='1' LIMIT 1 --
Password:  anything
```
The query always returns the first user, bypassing authentication.

### 3. SQL Injection — Block all registrations

On the Register screen, enter as the username:
```
' OR '1'='1' --
```
The duplicate-check always returns a row, so the app permanently reports "user already exists".

### 4. SQL Injection — Data extraction (UNION)

On the System screen, enter in the search box:
```
' UNION SELECT id, username, email, id FROM user --
```
The full user table — including usernames and emails — is displayed in the customer list.

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
