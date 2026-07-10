#!/usr/bin/env bash
# send_linux_events.sh
#
# Reads Linux log files, parses security events, and sends them to the
# Security Event Correlator API.
#
# Covers rules:
#   ssh_brute_force              — failed SSH logins       (/var/log/auth.log)
#   privilege_escalation         — sudo after SSH login   (/var/log/auth.log)
#   sensitive_file_access        — sensitive path reads   (/var/log/audit/audit.log)
#   port_scan                    — high connection volume (/var/log/ufw.log)
#
# Requirements: python3, curl
#
# Usage:
#   export SEC_API_URL="http://localhost:8000"
#   export SEC_API_KEY="your-api-key"
#   ./scripts/send_linux_events.sh
#
# Optional env vars:
#   SEC_SOURCE    — tag events with this name (default: hostname)
#   SEC_LINES     — lines to read from each log file (default: 1000)
#   SEC_BATCH     — events per API request (default: 50)
#   SEC_VERBOSE   — set to 1 for debug output

set -euo pipefail

API_URL="${SEC_API_URL:-http://localhost:8000}"
API_KEY="${SEC_API_KEY:-}"
SOURCE="${SEC_SOURCE:-$(hostname -s 2>/dev/null || hostname)}"
LINES="${SEC_LINES:-1000}"
BATCH="${SEC_BATCH:-50}"
VERBOSE="${SEC_VERBOSE:-0}"

# ── Helpers ───────────────────────────────────────────────────────────────────

log()  { echo "[$(date +%H:%M:%S)] $*" >&2; }
die()  { log "ERROR: $*"; exit 1; }

[[ -n "$API_KEY" ]] || die "SEC_API_KEY is not set."

detect_first_readable() {
    for f in "$@"; do [[ -r "$f" ]] && echo "$f" && return; done; echo ""
}

AUTH_LOG=$(detect_first_readable /var/log/auth.log /var/log/secure)
UFW_LOG=$(detect_first_readable /var/log/ufw.log /var/log/kern.log)
AUDIT_LOG=$(detect_first_readable /var/log/audit/audit.log)

log "Security Event Correlator — Linux log sender"
log "Source: $SOURCE  →  $API_URL"
log ""
log "Log files:"
log "  auth.log  : ${AUTH_LOG:-not found (failed logins + sudo not parsed)}"
log "  ufw.log   : ${UFW_LOG:-not found (port_scan rule needs this)}"
log "  audit.log : ${AUDIT_LOG:-not found (sensitive_file_access rule needs this)}"
log ""

# ── Parse and send (Python3 handles JSON encoding and regex reliably) ─────────

python3 - "$AUTH_LOG" "$UFW_LOG" "$AUDIT_LOG" \
           "$SOURCE" "$API_URL" "$API_KEY" \
           "$LINES" "$BATCH" "$VERBOSE" << 'PYTHON'

import json
import os
import re
import sys
from datetime import datetime
from urllib.request import urlopen, Request
from urllib.error import HTTPError, URLError

auth_log, ufw_log, audit_log, source, api_url, api_key, \
    lines_str, batch_str, verbose_str = sys.argv[1:10]

LINES      = int(lines_str)
BATCH_SIZE = int(batch_str)
VERBOSE    = (verbose_str == "1")
YEAR       = datetime.now().year


def vlog(msg):
    if VERBOSE:
        print(f"    {msg}", file=sys.stderr)


def tail(path, n):
    """Return the last n lines of a file, or [] if missing/unreadable."""
    if not path or not os.path.isfile(path):
        return []
    try:
        with open(path, errors="replace") as f:
            return f.readlines()[-n:]
    except PermissionError:
        print(f"  [WARN] Cannot read {path} — try running with sudo", file=sys.stderr)
        return []


def to_iso(month, day, time_str):
    """Convert auth.log 'Jul  7 12:34:56' fields to ISO 8601 UTC string."""
    try:
        return datetime.strptime(
            f"{month} {int(day):02d} {time_str} {YEAR}", "%b %d %H:%M:%S %Y"
        ).strftime("%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")


# ── auth.log ──────────────────────────────────────────────────────────────────
# Covers: ssh_brute_force, privilege_escalation_after_login

_SSH_FAILED = re.compile(
    r"^(\w{3})\s+(\d+)\s+([\d:]+)\s+\S+\s+sshd\[\d+\]:\s+"
    r"Failed password for (?:invalid user )?(\S+) from ([\d.a-fA-F:.]+) port (\d+)"
)
_SSH_OK = re.compile(
    r"^(\w{3})\s+(\d+)\s+([\d:]+)\s+\S+\s+sshd\[\d+\]:\s+"
    r"Accepted \S+ for (\S+) from ([\d.a-fA-F:.]+) port (\d+)"
)
# sudo:   john : TTY=pts/0 ; PWD=/home/john ; USER=root ; COMMAND=/bin/bash
_SUDO = re.compile(
    r"^(\w{3})\s+(\d+)\s+([\d:]+)\s+\S+\s+sudo:\s+(\S+)\s*:.*?USER=(\S+).*?COMMAND=(.+)$"
)


def parse_auth_log(lines):
    events = []
    for line in lines:
        line = line.rstrip()

        m = _SSH_FAILED.match(line)
        if m:
            events.append({
                "timestamp":  to_iso(m.group(1), m.group(2), m.group(3)),
                "source":     source,
                "event_type": "login_attempt",
                "severity":   "medium",
                "user":       m.group(4),
                "action":     "failed",
                "resource":   "/ssh",
                "details":    {"ip": m.group(5), "port": int(m.group(6))},
                "raw_log":    line,
            })
            continue

        m = _SSH_OK.match(line)
        if m:
            events.append({
                "timestamp":  to_iso(m.group(1), m.group(2), m.group(3)),
                "source":     source,
                "event_type": "login_attempt",
                "severity":   "low",
                "user":       m.group(4),
                "action":     "succeeded",
                "resource":   "/ssh",
                "details":    {"ip": m.group(5), "port": int(m.group(6))},
                "raw_log":    line,
            })
            continue

        m = _SUDO.match(line)
        if m:
            events.append({
                "timestamp":  to_iso(m.group(1), m.group(2), m.group(3)),
                "source":     source,
                "event_type": "privilege_change",
                "severity":   "high",
                "user":       m.group(4),
                "action":     "succeeded",
                "resource":   m.group(6).strip(),
                "details":    {"escalated_to": m.group(5)},
                "raw_log":    line,
            })

    return events


# ── ufw.log ───────────────────────────────────────────────────────────────────
# Covers: port_scan
# Example line:
#   Jul  7 12:34:56 host kernel: [1234.5] [UFW BLOCK] IN=eth0 SRC=10.0.0.1 DST=192.168.1.1 ... DPT=22 ...

_UFW = re.compile(
    r"^(\w{3})\s+(\d+)\s+([\d:]+).*\[UFW (ALLOW|BLOCK)\]"
    r".*\bSRC=([\d.a-fA-F:.]+)\b.*\bDST=([\d.a-fA-F:.]+)\b.*\bDPT=(\d+)\b"
)


def parse_ufw_log(lines):
    events = []
    for line in lines:
        m = _UFW.search(line)
        if not m:
            continue
        events.append({
            "timestamp":  to_iso(m.group(1), m.group(2), m.group(3)),
            "source":     source,
            "event_type": "network_connection",
            "severity":   "low",
            "user":       None,
            "action":     "succeeded" if m.group(4) == "ALLOW" else "failed",
            "resource":   f"{m.group(6)}:{m.group(7)}",
            "details": {
                "ip":               m.group(5),
                "dst_ip":           m.group(6),
                "destination_port": int(m.group(7)),
            },
            "raw_log":    line.rstrip(),
        })
    return events


# ── audit.log ─────────────────────────────────────────────────────────────────
# Covers: sensitive_file_access
# Requires auditd with a file-watch rule, e.g.:
#   auditctl -w /etc/passwd -p r -k sensitive_files
#
# Pairs SYSCALL and PATH records by their shared audit serial number.

_SYSCALL = re.compile(
    r"type=SYSCALL msg=audit\((\d+\.\d+):(\d+)\):.*\buid=(\d+)\b.*\bcomm=\"([^\"]+)\".*\bexe=\"([^\"]+)\""
)
_PATH_REC = re.compile(
    r"type=PATH msg=audit\(\d+\.\d+:(\d+)\):.*\bname=\"([^\"]+)\""
)
_SENSITIVE = [
    "/etc/passwd", "/etc/shadow", "/etc/sudoers",
    "/.ssh/", "/root/", "authorized_keys",
    "id_rsa", "id_ed25519", "id_ecdsa",
    ".bash_history", "/var/log/auth", "/var/log/secure",
]


def is_sensitive(path):
    pl = path.lower()
    return any(p in pl for p in _SENSITIVE)


def parse_audit_log(lines):
    # Build serial → syscall metadata map first, then match PATH records.
    syscalls = {}
    events   = []

    for line in lines:
        line = line.rstrip()

        m = _SYSCALL.match(line)
        if m:
            syscalls[m.group(2)] = {
                "ts":   datetime.utcfromtimestamp(float(m.group(1))).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "uid":  m.group(3),
                "comm": m.group(4),
                "exe":  m.group(5),
            }
            continue

        m = _PATH_REC.match(line)
        if m:
            serial, path = m.group(1), m.group(2)
            if is_sensitive(path) and serial in syscalls:
                sc = syscalls[serial]
                events.append({
                    "timestamp":  sc["ts"],
                    "source":     source,
                    "event_type": "file_access",
                    "severity":   "high",
                    "user":       sc["uid"],   # UID string; no /etc/passwd lookup to keep it simple
                    "action":     "succeeded",
                    "resource":   path,
                    "details":    {"exe": sc["exe"], "comm": sc["comm"]},
                    "raw_log":    line,
                })

    return events


# ── Send ──────────────────────────────────────────────────────────────────────

def send_batch(events):
    # Remove None values so the API doesn't receive null user fields.
    clean = [{k: v for k, v in e.items() if v is not None} for e in events]
    payload = json.dumps(clean).encode()
    req = Request(
        f"{api_url}/v1/events/ingest",
        data=payload,
        headers={"Content-Type": "application/json", "X-API-Key": api_key},
        method="POST",
    )
    try:
        with urlopen(req, timeout=30) as resp:
            return json.loads(resp.read()).get("events_ingested", 0)
    except HTTPError as e:
        print(f"  [ERROR] HTTP {e.code}: {e.read().decode(errors='replace')[:200]}", file=sys.stderr)
        return 0
    except URLError as e:
        print(f"  [ERROR] Connection failed: {e.reason}", file=sys.stderr)
        return 0


def send_all(events):
    total = 0
    batches = (len(events) + BATCH_SIZE - 1) // BATCH_SIZE
    for i in range(0, len(events), BATCH_SIZE):
        batch  = events[i:i + BATCH_SIZE]
        sent   = send_batch(batch)
        total += sent
        vlog(f"Batch {i // BATCH_SIZE + 1}/{batches}: {sent}/{len(batch)} ingested")
    return total


# ── Main ──────────────────────────────────────────────────────────────────────

all_events = []

for label, path, parser in [
    ("auth.log ", auth_log,  parse_auth_log),
    ("ufw.log  ", ufw_log,   parse_ufw_log),
    ("audit.log", audit_log, parse_audit_log),
]:
    lines = tail(path, LINES)
    if lines:
        parsed = parser(lines)
        print(f"  {label}: {len(parsed):4d} events parsed from {path}", file=sys.stderr)
        all_events.extend(parsed)
    else:
        print(f"  {label}: skipped (not found or not readable)", file=sys.stderr)

if not all_events:
    print("\n[WARN] No events parsed from any log file.", file=sys.stderr)
    sys.exit(0)

# Sort chronologically so the rules engine sees events in arrival order.
all_events.sort(key=lambda e: e["timestamp"])

print(f"\n  Total: {len(all_events)} events → {api_url}", file=sys.stderr)
ingested = send_all(all_events)
print(f"  Done:  {ingested}/{len(all_events)} events accepted by API", file=sys.stderr)

PYTHON
