# Brute-Force Login Detection System

 🔗 **Live Demo:** https://brute-force-detector-theta.vercel.app/

A simple, self-contained Flask project that demonstrates how to detect and
block brute-force login attempts in real time.

## How it works

- Every login attempt (`/` form or `/api/login`) is recorded with its IP,
  username, and outcome.
- `detector.py` tracks failed attempts **per IP** and **per username** using
  a sliding time window (default: **5 failed attempts within 60 seconds**).
- Once the threshold is crossed, that IP/username is **auto-blocked** for a
  cooldown period (default: **5 minutes**) and an alert is logged.
- A successful login resets the failure counter.
- A live dashboard (`/dashboard`) polls the backend every 2 seconds and shows:
  - Recent login attempts
  - Active alerts
  - Currently blocked IPs/usernames
- All events are also written to `logs/login_attempts.log` and
  `logs/alerts.log` as JSON lines, so they can be shipped to a SIEM or
  analyzed later.

## Project structure

```
brute_force_detector/
├── app.py                  # Flask app: login page, JSON API, dashboard
├── detector.py              # Core brute-force detection engine
├── simulate_attack.py       # Script to simulate an attack against the running app
├── test_detector.py         # Unit tests for the detection logic
├── requirements.txt
├── templates/
│   ├── login.html
│   └── dashboard.html
├── static/
│   └── style.css
└── logs/                     # Created automatically; JSON-line logs
```

## Setup

```bash
cd brute_force_detector
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

## Run the app

```bash
python app.py
```

Then open:
- **Login page:** http://127.0.0.1:5000/
- **Dashboard:** http://127.0.0.1:5000/dashboard

Demo credentials: `admin / admin123`, `alice / wonderland`, `bob / builder2024`.

## Simulate a brute-force attack

With the app running in one terminal, run this in another:

```bash
# Single attacker IP hammering the "admin" account
python simulate_attack.py --ip 198.51.100.42 --user admin --attempts 7

# Distributed attack from multiple IPs
python simulate_attack.py --distributed --num-ips 4 --attempts 5 --user admin
```

Watch the dashboard update live: failed attempts pile up, an alert fires, and
the IP gets blocked — further attempts return `429 Too Many Requests` until
the cooldown expires.

## Run the tests

```bash
python -m pytest test_detector.py -v
```

## Configuration

Tune detection sensitivity in `app.py`:

```python
detector = BruteForceDetector(
    failed_attempt_threshold=5,   # failed attempts allowed...
    window_seconds=60,            # ...within this many seconds...
    block_seconds=300,            # ...before blocking for this long
)
```

## Deploying to Vercel

This project is already set up for Vercel (`vercel.json` + `api/index.py`).

**Option A — from your computer (needs Node.js installed):**
```bash
npm install -g vercel
cd brute_force_detector
vercel login
vercel
```
Answer the setup questions (defaults are fine), then `vercel` gives you a live URL.
Run `vercel --prod` to push it live permanently instead of a preview link.

**Option B — from GitHub (no command line needed):**
1. Push this folder to a new GitHub repository.
2. Go to https://vercel.com → **Add New Project** → import that repo.
3. Vercel auto-detects the Python config from `vercel.json`. Just click **Deploy**.
4. You'll get a live URL like `your-project.vercel.app`.

### Important limitation on Vercel

Vercel runs your app "serverless" — it doesn't keep a single process running
all the time like a normal server does. That means the detector's memory
(blocked IPs, failure counts) can reset between requests, so blocking may
not always hold consistently in production. It's fine for demos and
testing the logic. For real, reliable blocking in production, swap the
in-memory storage in `detector.py` for a small external store like
**Vercel KV** (Redis) — ask if you'd like this added.

## Notes / extending this project

- This is a **demonstration** system: passwords are stored in plaintext in
  a dict for simplicity. In production, use hashed passwords (bcrypt/argon2)
  and a real database.
- Detection state is **in-memory**; restarting the app clears blocks/counters.
  For production use, back it with Redis or a database so state survives
  restarts and works across multiple app instances.
- You could extend this with: email/Slack alerting, CAPTCHA after N failures
  instead of a hard block, geo-IP anomaly detection, or integration with
  fail2ban / a firewall to block at the network layer.
