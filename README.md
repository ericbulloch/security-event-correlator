# security-event-correlator
A security analytics platform that normalizes security events from multiple sources and uses AI-powered correlation to detect attack patterns that rule-based systems miss.

---

## Getting Started

### Prerequisites

- [Docker Desktop](https://www.docker.com/products/docker-desktop/) (includes Docker Compose)
- An API key for your chosen AI provider — **or** use `AI_PROVIDER=dummy` to skip AI entirely while testing the rules engine

---

### 1. Copy and configure the environment file

```bash
cp .env.example .env
```

Open `.env` and update the following:

| Variable | What to change |
|---|---|
| `POSTGRES_PASSWORD` | Set a strong password — Docker will use this to create the database |
| `RABBITMQ_PASSWORD` | Set a strong password — Docker will use this for the message broker |
| `AI_PROVIDER` | Choose `anthropic`, `gemini`, `github_copilot`, or `dummy` |
| `ANTHROPIC_API_KEY` / `GEMINI_API_KEY` / `GITHUB_TOKEN` | Set the key for whichever provider you chose (leave the others blank) |

> **Note:** `DATABASE_URL` and `RABBITMQ_URL` in `.env` are only used when running services outside Docker. The Docker containers use their own internal network addresses automatically.

---

### 2. Copy and configure the rules file

```bash
cp config/rules.yml.example config/rules.yml
```

The defaults are ready to use. Edit `config/rules.yml` if you want to:
- Disable a rule (`enabled: false`)
- Tune a threshold (e.g. raise `ssh_brute_force.threshold` from 5 to 7)

---

### 3. Build and start all services

```bash
docker compose up --build -d
```

This starts four containers: PostgreSQL, RabbitMQ, the API, and the correlation worker.  
The API container automatically runs `alembic upgrade head` on startup, so **no separate migration step is needed**.

Wait for all services to be healthy:

```bash
docker compose ps
```

All four services should show `healthy` or `running` before you proceed.

---

### 4. Seed the development API key

```bash
docker compose exec api python scripts/seed_dev.py
```

This creates a `local-dev` API key and prints it to the terminal. **Copy the key — it is only shown once.**

```
Dev API key created:
  Client: local-dev
  Key:     <your-key-here>
```

> To use a fixed key instead of a random one (useful for scripting), set `DEV_API_KEY=your-chosen-key` in `.env` before running the seed script.

---

### 5. Verify the API is running

```bash
curl http://localhost:8000/health
```

Expected response:

```json
{"status": "healthy", "events_stored": 0}
```

---

### 6. Send a test event

Replace `<your-key>` with the key printed in step 4:

```bash
curl -X POST http://localhost:8000/v1/events/ingest \
  -H "Content-Type: application/json" \
  -H "X-API-Key: <your-key>" \
  -d '[{
    "timestamp": "'"$(date -u +%Y-%m-%dT%H:%M:%SZ)"'",
    "source":     "test-machine",
    "event_type": "login_attempt",
    "severity":   "medium",
    "user":       "root",
    "action":     "failed",
    "resource":   "/ssh",
    "details":    {"ip": "10.0.0.1", "port": 22}
  }]'
```

---

### Sending real log data

Two scripts are included to parse real log files and send events to the API:

**Linux** (parses `/var/log/auth.log`, `/var/log/audit/audit.log`, `/var/log/ufw.log`):

```bash
# Make the script executable (first time only)
chmod +x scripts/send_linux_events.sh

export SEC_API_URL="http://localhost:8000"
export SEC_API_KEY="<your-key>"
bash scripts/send_linux_events.sh
```

**Windows** (reads Windows Security Event Log and the Windows Firewall log — run PowerShell as Administrator):

```powershell
$env:SEC_API_URL = "http://localhost:8000"
$env:SEC_API_KEY = "<your-key>"
.\scripts\Send-WindowsEvents.ps1
```

---

### View alerts

After events are processed, retrieve the generated alerts:

```bash
# All alerts (most recent first, up to 50)
curl -H "X-API-Key: <your-key>" http://localhost:8000/v1/alerts

# Filter by severity
curl -H "X-API-Key: <your-key>" "http://localhost:8000/v1/alerts?severity=critical"

# Paginate
curl -H "X-API-Key: <your-key>" "http://localhost:8000/v1/alerts?limit=10&offset=10"
```

---

### Demo: simulating an attack

The following curl commands simulate the classic CTF kill chain and trigger all four detection rules. Replace `<your-key>` and run them in order.

**Step 1 — SSH brute force (triggers `ssh_brute_force` alert)**

Send 5 failed login attempts in quick succession:

```bash
for i in 1 2 3 4 5; do
  curl -s -X POST http://localhost:8000/v1/events/ingest \
    -H "Content-Type: application/json" \
    -H "X-API-Key: <your-key>" \
    -d '[{"timestamp":"'"$(date -u +%Y-%m-%dT%H:%M:%SZ)"'","source":"target-box","event_type":"login_attempt","severity":"medium","user":"root","action":"failed","resource":"/ssh","details":{"ip":"10.0.0.1","port":22}}]'
  sleep 1
done
```

**Step 2 — Successful login (context for privilege escalation)**

```bash
curl -s -X POST http://localhost:8000/v1/events/ingest \
  -H "Content-Type: application/json" \
  -H "X-API-Key: <your-key>" \
  -d '[{"timestamp":"'"$(date -u +%Y-%m-%dT%H:%M:%SZ)"'","source":"target-box","event_type":"login_attempt","severity":"low","user":"root","action":"succeeded","resource":"/ssh","details":{"ip":"10.0.0.1","port":22}}]'
```

**Step 3 — Privilege escalation (triggers `privilege_escalation_after_login` alert)**

```bash
curl -s -X POST http://localhost:8000/v1/events/ingest \
  -H "Content-Type: application/json" \
  -H "X-API-Key: <your-key>" \
  -d '[{"timestamp":"'"$(date -u +%Y-%m-%dT%H:%M:%SZ)"'","source":"target-box","event_type":"privilege_change","severity":"high","user":"root","action":"succeeded","resource":"/bin/bash","details":{"escalated_to":"root"}}]'
```

**Step 4 — Sensitive file access (triggers `sensitive_file_access` alert)**

```bash
curl -s -X POST http://localhost:8000/v1/events/ingest \
  -H "Content-Type: application/json" \
  -H "X-API-Key: <your-key>" \
  -d '[{"timestamp":"'"$(date -u +%Y-%m-%dT%H:%M:%SZ)"'","source":"target-box","event_type":"file_access","severity":"high","user":"root","action":"succeeded","resource":"/etc/shadow","details":{"exe":"/usr/bin/cat"}}]'
```

**Check the alerts** (give the worker a few seconds to process):

```bash
sleep 5
curl -H "X-API-Key: <your-key>" http://localhost:8000/v1/alerts | python3 -m json.tool
```

You should see three alerts: `ssh_brute_force` (high), `privilege_escalation_after_login` (critical), and `sensitive_file_access` (high).

> **Tip:** Set `AI_PROVIDER=dummy` in `.env` while running this demo to skip AI calls and see only the deterministic rules fire cleanly.

---

### Updating rule configuration

`config/rules.yml` is mounted into the containers as a read-only volume. After editing the file you only need to restart the services — no rebuild required:

```bash
docker compose restart api worker
```

---

### Useful commands

```bash
# View live logs for all services
docker compose logs -f

# View logs for just the correlation worker
docker compose logs -f worker

# Stop all services (data is preserved in the postgres_data volume)
docker compose down

# Stop all services AND delete all data
docker compose down -v

# Rebuild after code changes
docker compose up --build -d
```

## Roadmap

1. Add threat intelligence feeds (VirusTotal, MISP, AlienVault OTX) to enrich events before the rules engine runs.
2. UEBA (User and Entity Behavior Analytics) to learn what "normal" looks like per user/host and alerting on deviations. Alerts will be able to fire on statistical anomalies.
3. MITRE ATT&CK mapping so that alerts can be tagged with technique IDs (T1110.001 etc.). Analysts will know immediately where in the kill chain an alert falls.
4. Exceptional case handling so that alerts will never fire on brute force attempts from a vulnerability scanner IP address.
5. Ability to create incidents and group related alerts into a single investigation.
6. Escalation policies so that a critical alert will auto-escalate if nobody acknowleges it within 15 minutes.
7. Notifications through email and Slack when a critical alert fires.
8. Add playbooks with structured response steps attached to an alert type. i.e. When a brute force happens: 1) check if account is locked, 2) check for successful login after, 3) escalate if yes
9. Audit trail of the SIEM itself. The system should be able to answer questions like: Who viewed alert X? Who changed its status?
10. Compliance reports for auditors who want evidence of things like "we logged all privileged access for the last 90 days".
11. Searching & threat hunting. Currently there is no way to ask ad-hoc questions like "show me all events for this IP address in the last 30 days".
12. There are only a handful of rules. Many more rules need to be added.
13. Rule tuning UI. Currently changing a threshold means editing a YAML file and redeploying. Analysts need to tune a rule without touching code.
