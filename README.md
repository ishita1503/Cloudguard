# CloudGuard – Cloud Security Monitoring & Honeypot System

A simple college **Cloud Computing microproject**.
A Flask application hosted on **Render** watches for suspicious activity, using fake "honeypot" pages, and saves every security event in a **Supabase cloud PostgreSQL database**. An admin dashboard shows the events, risk levels, a chart, alerts and reports.

---

## 1. Project Overview

Companies put their applications on the cloud, and attackers scan the internet looking for login pages, admin pages and APIs to attack. CloudGuard places fake (decoy) pages on the cloud. Nobody has a reason to open them, so whoever does is suspicious. Each visit is saved with an IP address, a time and a **risk level**. Because the data lives in a cloud database, the admin can watch it from any device.

## 2. Features

- Admin login with Flask sessions (no JWT, no tokens)
- Honeypot pages: `/honeypot/login`, `/honeypot/admin`, `/honeypot/api`
- Login monitoring (successful and failed logins are recorded)
- Simple rule-based risk score and risk level
- Dashboard: 4 cards, recent events table, Chart.js graph, High/Critical alerts (auto-refreshes every 5 seconds)
- Demo buttons: Simulate Failed Login / Honeypot Access / Critical Activity
- Reports page: totals, most accessed honeypot endpoint, most frequent IP
- Data stored in a cloud database, so every device sees the same data

## 3. Architecture

```
 User / Attacker (any device)
          |
          v
      Internet
          |
          v
  Render  (Flask application, cloud hosting)
          |
          |-- Honeypot pages  (fake login / admin / API)
          |-- Login monitoring
          |-- Risk scoring
          v
  Supabase PostgreSQL  (cloud database: security_events table)
          |
          v
  Dashboard + Reports  (admin opens the Render URL from any device)
```

## 4. Technologies

| Part | Technology |
|---|---|
| Frontend | HTML, CSS, JavaScript, Chart.js |
| Backend | Python, Flask |
| Cloud hosting | Render |
| Cloud database | Supabase (PostgreSQL) |
| Python libraries | Flask, psycopg2-binary, gunicorn, python-dotenv |

## 5. Project Structure

```
cloudguard/
├── app.py              <- all backend logic (routes, risk rules, database)
├── requirements.txt
├── .env.example        <- copy to .env and fill in
├── .gitignore
├── README.md
├── templates/          <- login, dashboard, reports, 3 honeypot pages
└── static/             <- style.css, script.js
```

## 6. Database

One table, created automatically when the app first runs:

| Field | Meaning |
|---|---|
| id | Event number (auto) |
| timestamp | Date and time of the event |
| ip_address | IP of the visitor |
| activity | What happened (e.g. "Failed login") |
| endpoint | Which page (e.g. `/honeypot/admin`) |
| risk_score | Number from 10 to 90 |
| risk_level | Low / Medium / High / Critical |

SQL (if you ever want to create it by hand in the Supabase SQL Editor):

```sql
CREATE TABLE IF NOT EXISTS security_events (
    id          SERIAL PRIMARY KEY,
    timestamp   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ip_address  VARCHAR(45) NOT NULL,
    activity    TEXT NOT NULL,
    endpoint    TEXT NOT NULL,
    risk_score  INTEGER NOT NULL,
    risk_level  VARCHAR(10) NOT NULL
);
```

Passwords are **never** stored.

## 7. How the Honeypot Works

1. The three fake pages look like a real server login, admin panel and API.
2. They contain no real data. They only record the visitor.
3. When someone opens one, the app saves: IP, time, page, activity, risk score, risk level.
4. If the same IP hits honeypot pages 5 times within 10 minutes, the event becomes **Critical**.
5. A small note on each fake page says it is a decoy (you can delete that line in the HTML if you want the page to look fully real).

## 8. Risk Scoring

| Event | Score |
|---|---|
| Normal activity (successful login) | 10 |
| Failed login | 20 |
| Repeated failed login (3 or more from the same IP in 10 min) | 50 |
| Honeypot login / API page | 60 |
| Honeypot admin page | 70 |
| Critical / repeated suspicious activity (10 failed logins, or 5 honeypot hits) | 90 |

| Score | Risk level |
|---|---|
| 0 – 24 | Low |
| 25 – 49 | Medium |
| 50 – 74 | High |
| 75 – 100 | Critical |

All the rules are at the top of `app.py` under "RISK RULES".

## 9. Local Setup

You need Python 3.10+ and a Supabase database (see section 10).

```bash
# 1. go into the project folder
cd cloudguard

# 2. (optional but recommended) virtual environment
python -m venv venv
venv\Scripts\activate          # Windows
# source venv/bin/activate     # Mac / Linux

# 3. install libraries
pip install -r requirements.txt

# 4. create your .env file
copy .env.example .env         # Windows
# cp .env.example .env         # Mac / Linux
```

Open `.env` and paste your Supabase `DATABASE_URL`. Then run:

```bash
python app.py
```

Open **http://127.0.0.1:5000** and log in with `admin / admin123`.

## 10. Supabase Setup (Cloud Database)

1. Go to https://supabase.com, sign up and click **New project**.
2. Give it a name, set a **database password** (save it!) and choose the region nearest to you.
3. Wait until the project is ready. Click the **Connect** button at the top of the project.
4. Copy the **PostgreSQL connection string**. Use the **Session pooler** one if the direct one does not work (some hosts, including free Render, cannot reach the direct connection).
5. Replace `[YOUR-PASSWORD]` in it with your real password. If the password has special characters like `@` or `#`, replace them with URL codes (`@` = `%40`, `#` = `%23`) or choose a simple password.
6. Paste the final string into `.env` as `DATABASE_URL=...` (and later into Render).
7. Run the app once. Then open **Table Editor** in Supabase: the `security_events` table is there.

## 11. Render Deployment (Cloud Hosting)

1. Upload the project to a **GitHub** repository. Make sure `.env` is NOT uploaded (the `.gitignore` already blocks it).
2. Go to https://render.com and sign up with GitHub.
3. Click **New +** → **Web Service** → choose your repository.
4. Fill in:
   - **Runtime / Language:** Python 3
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `gunicorn app:app`
   - **Instance type:** Free
5. Open **Environment Variables** and add:

| Key | Value |
|---|---|
| `DATABASE_URL` | your Supabase connection string |
| `SECRET_KEY` | any long random text |
| `ADMIN_USERNAME` | `admin` |
| `ADMIN_PASSWORD` | `admin123` (or a stronger one) |
| `PYTHON_VERSION` | `3.12.3` |

6. Click **Create Web Service** and wait for the deploy to finish.
7. Render gives you a URL like `https://cloudguard-xxxx.onrender.com`. Open it from any device.

Notes:
- On the free plan Render goes to sleep when nobody uses it, so the first page load can take around a minute. Open the URL before your demo.
- Free Supabase projects can pause after a long time without use. If that happens, press **Restore** in the Supabase dashboard.

## 12. How to Test

1. Open your Render URL (or http://127.0.0.1:5000 locally).
2. **Failed logins:** type a wrong password 3 times. Event 3 becomes "Repeated failed login" (High).
3. Log in with `admin / admin123`. The dashboard opens and "Successful login" is recorded.
4. Click the three demo buttons. The cards, table, chart and alerts update.
5. Click the honeypot links on the dashboard (or open `/honeypot/admin` yourself). A new event appears with score 70 (High).
6. Open `/honeypot/admin` 5 times quickly. The 5th hit is **Critical**.
7. Open the **Reports** page and check the totals, top endpoint and top IP.
8. **Cloud proof:** open the Render URL on your phone. Log in and create an event there. Watch it show up on the laptop dashboard within 5 seconds. Also look at the `security_events` table in the Supabase Table Editor.

## 13. Future Scope

- Email or SMS alerts for Critical events
- Block suspicious IPs automatically
- Show IP location on a map
- More honeypot pages and fake services
- Machine learning for smarter detection
- Multiple admin users with roles

---

# Viva Questions and Answers

**1. What is cloud computing?**
Using computers, storage and databases over the internet, owned by another company, instead of buying and running our own. We pay only for what we use (or use a free plan).

**2. What is a honeypot?**
A fake system or page that looks real but has nothing valuable. Its only job is to attract attackers and record what they do.

**3. Why did you use a honeypot?**
No genuine user will open a fake admin page, so any visit is suspicious. This gives early warning without checking every real request.

**4. What is CloudGuard?**
A cloud-hosted security monitoring system. It has honeypot pages, login monitoring, risk scoring and a dashboard, and all data is stored in a cloud database.

**5. How are suspicious activities detected?**
Two ways: (a) any visit to a honeypot page, and (b) repeated failed logins from the same IP address.

**6. How is risk calculated?**
With simple rules. Each event gets a score (normal 10, failed login 20, repeated failed login 50, honeypot 60 or 70, repeated suspicious activity 90). The score is changed into Low (0–24), Medium (25–49), High (50–74) or Critical (75–100). There is no machine learning.

**7. Why did you use a cloud database (Supabase PostgreSQL)?**
So all events are stored in one central place that every device can see, and the data is safe even if the web server restarts. A local file would be lost or separate on each machine.

**8. Why did you use Flask?**
It is small, easy to learn and needs very little code. It is enough for a few pages, sessions and database queries.

**9. Why did you use Render?**
It hosts a Flask app directly from GitHub with a free plan, so the project gets a public URL and can be used from anywhere.

**10. What information is stored?**
Date and time, IP address, activity, page (endpoint), risk score and risk level. Passwords are never stored.

**11. What happens when someone accesses `/honeypot/admin`?**
The page shows a fake admin screen with no real data. The app reads the visitor's IP, gives the event a score of 70 (High), saves it in the `security_events` table, and the admin sees it on the dashboard with an alert. If the same IP does it 5 times in 10 minutes, it becomes Critical (90).

**12. How is the login protected?**
The admin logs in with a username and password. Flask creates a session, and only logged-in users can open the dashboard and reports. There are no tokens or JWT.

**13. What is the cloud part of your project?**
Cloud hosting (Render), a cloud database (Supabase), centralized logging, remote access from any device, and cloud-based monitoring.

**14. What is the future scope?**
Email alerts, automatic IP blocking, IP location map, more honeypot services, machine learning and multiple admin users.
