# Wiz Security Monitoring Playbook

## Overview

Automated playbook that polls the Wiz GraphQL API every 5 minutes to pull workload scan logs, attack surface scan logs, and cloud events, filters them into a custom dashboard, and fires alerts whenever a new issue crosses a severity threshold.

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                     Scheduler (cron / APScheduler)       │
│                     Fires every 5 minutes                │
└───────────────────────────┬─────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────┐
│                  wiz_playbook.py  (main)                  │
│                                                           │
│  1. Authenticate  →  OAuth2 token (cached, auto-refresh) │
│  2. Pull data     →  3 parallel GraphQL queries           │
│  3. Filter        →  severity / status / time window      │
│  4. Diff          →  compare to last run (state file)     │
│  5. Alert         →  Slack / Email / PagerDuty on new     │
│  6. Dashboard     →  regenerate index.html                │
└───────┬───────────────┬───────────────┬──────────────────┘
        │               │               │
        ▼               ▼               ▼
  Workload Scan   Attack Surface   Cloud Events
  Issues API       Issues API        API
```

---

## File Structure

```
Wiz/
├── PLAYBOOK.md                  ← this file
├── config.yaml                  ← all tuneable knobs (no secrets)
├── wiz_playbook.py              ← main script
├── requirements.txt             ← Python dependencies
├── dashboard/
│   └── index.html               ← generated dashboard (overwritten each run)
├── state/
│   └── last_run.json            ← persisted state: known issue IDs + last cursor
└── logs/
    └── wiz_playbook.log         ← rotating log
```

---

## Step 1 — Authentication

**Method:** OAuth 2.0 Client Credentials flow.

| Field | Value |
|-------|-------|
| Token URL | `https://auth.app.wiz.io/oauth/token` |
| Grant type | `client_credentials` |
| Audience | `wiz-api` |
| Credentials | `WIZ_CLIENT_ID` / `WIZ_CLIENT_SECRET` env vars |

The script caches the token in memory and refreshes it automatically before expiry (`expires_in - 60s` buffer).

---

## Step 2 — Data Pull (GraphQL Queries)

All three queries run against the regional endpoint configured in `config.yaml` (e.g. `https://api.us20.app.wiz.io/graphql`). Each uses cursor-based pagination to retrieve all matching pages per run.

### 2a — Workload Scan Issues

Targets issues created by Wiz's agentless workload scanner: OS vulnerabilities, misconfigurations, exposed secrets, malware findings.

```graphql
query WorkloadScanIssues($filterBy: IssueFilters, $first: Int, $after: String) {
  issues(filterBy: $filterBy, first: $first, after: $after) {
    nodes {
      id
      status
      severity
      type
      createdAt
      updatedAt
      entitySnapshot {
        id
        type          # VirtualMachine | ContainerImage | etc.
        name
        cloudPlatform
        region
        subscriptionId
        subscriptionName
      }
      control {
        id
        name
        description
        securitySubCategories {
          title
          category { name framework { name } }
        }
      }
      sourceRule { id name }
    }
    pageInfo { hasNextPage endCursor }
  }
}
```

**Filter variables applied:**
```json
{
  "filterBy": {
    "status": ["OPEN", "IN_PROGRESS"],
    "severity": ["CRITICAL", "HIGH", "MEDIUM"],
    "type": ["TOXIC_COMBINATION", "THREAT_DETECTION"],
    "createdAt": { "after": "<ISO timestamp of last run>" }
  },
  "first": 100
}
```

---

### 2b — Attack Surface Scan Issues

Targets externally exposed assets: open ports, internet-facing services, exposed APIs, risky public cloud configurations.

```graphql
query AttackSurfaceIssues($filterBy: IssueFilters, $first: Int, $after: String) {
  issues(filterBy: $filterBy, first: $first, after: $after) {
    nodes {
      id
      status
      severity
      type
      createdAt
      updatedAt
      entitySnapshot {
        id
        type          # NetworkInterface | LoadBalancer | StorageBucket | etc.
        name
        cloudPlatform
        region
        publicIpAddress
        dnsName
      }
      control {
        id
        name
        description
        securitySubCategories {
          title
          category { name framework { name } }
        }
      }
    }
    pageInfo { hasNextPage endCursor }
  }
}
```

**Filter variables applied:**
```json
{
  "filterBy": {
    "status": ["OPEN", "IN_PROGRESS"],
    "severity": ["CRITICAL", "HIGH", "MEDIUM"],
    "type": ["CLOUD_CONFIGURATION", "LATERAL_MOVEMENT"],
    "entityType": ["NETWORK_INTERFACE", "LOAD_BALANCER", "STORAGE_BUCKET",
                   "COMPUTE_INSTANCE", "MANAGED_DATABASE", "SERVERLESS"]
  },
  "first": 100
}
```

---

### 2c — Cloud Events

Pulls audit trail events from integrated cloud accounts (AWS CloudTrail, Azure Activity Log, GCP Audit Logs).

```graphql
query CloudEvents($filterBy: CloudEventFilters, $first: Int, $after: String) {
  cloudEvents(filterBy: $filterBy, first: $first, after: $after) {
    nodes {
      id
      eventType
      eventTime
      sourceIPAddress
      userAgent
      errorCode
      errorMessage
      cloudPlatform
      region
      subscriptionId
      subject {
        id
        name
        type
        nativeType
      }
      actor {
        id
        name
        type
        email
      }
    }
    pageInfo { hasNextPage endCursor }
  }
}
```

**Filter variables applied:**
```json
{
  "filterBy": {
    "eventTime": { "after": "<ISO timestamp of now - lookback_minutes>" },
    "eventType": [
      "ConsoleLogin", "DeleteBucket", "DeleteDBInstance",
      "StopInstances", "TerminateInstances", "CreateUser",
      "AttachRolePolicy", "DeleteTrail", "DisableKey",
      "UpdateAssumeRolePolicy"
    ]
  },
  "first": 100
}
```

---

## Step 3 — Filtering Logic

After raw data is fetched it is passed through a filter pipeline:

| Stage | Logic |
|-------|-------|
| **Severity gate** | Drop anything below configured minimum severity |
| **Status gate** | Keep only `OPEN` / `IN_PROGRESS` issues |
| **Time window** | For cloud events, keep only events newer than `now - lookback_minutes` |
| **Dedup** | Load `state/last_run.json`; skip issue IDs already seen in a previous run |
| **New-issue flag** | Mark issues not in the previous state as `is_new = True` — these drive alerts |

---

## Step 4 — Alerting

Alerts fire only for **new** issues with severity in `alerts.trigger_severities` (default: `CRITICAL`, `HIGH`).

### Slack

POST to the configured Incoming Webhook URL with a Block Kit message:

```
🚨 [CRITICAL] New Wiz Issue
Control:   S3 Bucket Publicly Accessible
Resource:  prod-data-bucket (us-east-1)
Account:   prod-aws-123456
Link:      https://app.wiz.io/issues/<id>
```

### Email (SMTP / TLS)

HTML email with the same fields, sent to all addresses in `alerts.email.recipients`.

### PagerDuty

POST to the Events API v2 with `severity` mapped:

| Wiz severity | PagerDuty severity |
|---|---|
| CRITICAL | critical |
| HIGH | error |
| MEDIUM | warning |

---

## Step 5 — Dashboard (index.html)

The dashboard is a self-contained HTML file regenerated every run. It requires no server — open it in any browser.

### Sections

| Section | Content |
|---------|---------|
| **Summary bar** | Total open issues by severity (CRITICAL / HIGH / MEDIUM / LOW) |
| **Workload Issues table** | Sortable: severity, resource name, cloud, region, control, age |
| **Attack Surface table** | Sortable: severity, asset type, public IP/DNS, control, age |
| **Cloud Events table** | Sortable: time, event type, actor, source IP, account |
| **Trend chart** | Line chart (Chart.js, CDN) — issue counts over last 24h snapshots |
| **Last updated** | Timestamp of the most recent poll |

### Colour coding

| Severity | Colour |
|----------|--------|
| CRITICAL | Red `#dc2626` |
| HIGH | Orange `#ea580c` |
| MEDIUM | Yellow `#ca8a04` |
| LOW | Blue `#2563eb` |

---

## Step 6 — State Persistence

After each successful run the script writes `state/last_run.json`:

```json
{
  "last_run_utc": "2026-05-05T12:00:00Z",
  "known_issue_ids": ["id1", "id2", "..."],
  "history": [
    {
      "timestamp": "2026-05-05T12:00:00Z",
      "critical": 3,
      "high": 12,
      "medium": 45,
      "cloud_events": 7
    }
  ]
}
```

`known_issue_ids` prevents re-alerting on the same issue across runs.  
`history` feeds the trend chart (capped at `max_history_snapshots`).

---

## Step 7 — Scheduler (5-minute Loop)

Two options — choose one based on environment:

### Option A: System cron (recommended for servers)

```cron
# Run every 5 minutes, append to log
*/5 * * * * /usr/bin/python3 /path/to/Wiz/wiz_playbook.py >> /path/to/logs/cron.log 2>&1
```

### Option B: Built-in APScheduler (for long-running processes / Docker)

The script itself enters a blocking loop when invoked with `--daemon`:

```bash
python3 wiz_playbook.py --daemon
```

Uses `APScheduler` with `BlockingScheduler` + `IntervalTrigger(seconds=300)`. Handles SIGTERM gracefully for container deployments.

### Option C: Claude Code `/loop` (for local development)

```
/loop 5m python3 wiz_playbook.py
```

---

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `WIZ_CLIENT_ID` | Yes | OAuth client ID from Wiz Settings > Service Accounts |
| `WIZ_CLIENT_SECRET` | Yes | OAuth client secret |
| `SLACK_WEBHOOK_URL` | If Slack enabled | Incoming webhook URL |
| `EMAIL_SENDER` | If email enabled | From address |
| `EMAIL_PASSWORD` | If email enabled | SMTP password / app password |
| `PAGERDUTY_INTEGRATION_KEY` | If PD enabled | Events API v2 integration key |

---

## Dependencies (requirements.txt)

```
requests>=2.31.0          # HTTP client for GraphQL calls and alert webhooks
PyYAML>=6.0               # config.yaml parsing
APScheduler>=3.10.0       # built-in daemon scheduler (Option B)
jinja2>=3.1.0             # HTML dashboard templating
```

---

## Wiz API Permissions Required

The Service Account used must have the following Wiz roles/scopes:

| Scope | Why |
|-------|-----|
| `read:issues` | Pull workload + attack surface issues |
| `read:cloud_events` | Pull cloud audit events |
| `read:resources` | Resolve entity details in issues |

Grant via: **Wiz Console → Settings → Service Accounts → Create → assign Reader role**.

---

## Quick Start

```bash
# 1. Clone / copy this directory
cd /path/to/Wiz

# 2. Install dependencies
pip install -r requirements.txt

# 3. Export secrets
export WIZ_CLIENT_ID="your-client-id"
export WIZ_CLIENT_SECRET="your-client-secret"
export SLACK_WEBHOOK_URL="https://hooks.slack.com/..."

# 4. Edit config.yaml — set api_endpoint to your region

# 5. Single run (test)
python3 wiz_playbook.py

# 6. Open the dashboard
open dashboard/index.html

# 7. Start daemon (runs every 5 minutes)
python3 wiz_playbook.py --daemon
```

---

## Alert Flow Diagram

```
New issue detected (is_new = True)
        │
        ▼
Severity ∈ trigger_severities?
    │           │
   YES          NO
    │           │
    ▼           ▼
Send alert   Log only
 (Slack /    (dashboard
  Email /     still
   PD)        updated)
```

---

## Extension Points

| Feature | How to add |
|---------|-----------|
| Webhook to SIEM (Splunk, Sentinel) | Add a `siem` section in `config.yaml` + HTTP POST in the alert module |
| Jira ticket creation | Use Wiz's native Jira integration, or POST to Jira REST API on new CRITICAL issues |
| Metrics export (Prometheus) | Expose a `/metrics` endpoint with `prometheus_client` library |
| Multi-tenant | Loop over multiple `[client_id, client_secret, endpoint]` tuples in config |
