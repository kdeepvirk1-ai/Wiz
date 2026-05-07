# Wiz — External Attack Surface Monitoring (Instance Lifecycle Playbook)

## Problem Statement

Wiz attack surface findings remain open for instances that have since been **terminated** and had their **public IPs released**. This creates noise that buries real exposures. This playbook solves that by correlating every attack surface finding against the current launch status of the underlying instance, then:

- **Suppressing** findings whose instance is terminated *and* whose public IP is no longer bound to any active resource.
- **Flagging** findings whose instance is stopped but whose IP is still reserved (dormant risk).
- **Escalating** findings whose instance is running with an active public exposure.

The dashboard surfaces only actionable findings, grouped by lifecycle state.

---

## Core Concept: Lifecycle States

Every attack surface finding is classified into one of four lifecycle buckets before it reaches the dashboard:

```
Finding
  │
  ├─ Instance RUNNING  + Public IP bound        →  ACTIVE EXPOSURE   (alert + show)
  │
  ├─ Instance STOPPED  + Public IP still bound  →  DORMANT RISK      (warn + show)
  │
  ├─ Instance STOPPED  + Public IP released     →  STALE FINDING     (suppress + log)
  │
  └─ Instance TERMINATED + Public IP released   →  RESOLVED (GHOST)  (suppress + log)
       │
       └─ Instance TERMINATED + IP still bound  →  ORPHANED IP       (alert + show)
            (Elastic IP / re-assignment — a new resource may have inherited the exposure)
```

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                   Scheduler  (every 5 minutes)                    │
└──────────────────────────────────┬───────────────────────────────┘
                                   │
                                   ▼
┌──────────────────────────────────────────────────────────────────┐
│             attack_surface_lifecycle.py  (main)                   │
│                                                                    │
│  Phase 1 – COLLECT                                                │
│    ├── Query A : Attack Surface Issues  (public-facing entities)  │
│    ├── Query B : Instance / Service resource state                │
│    └── Query C : Cloud Events  (Stop / Terminate / IP release)    │
│                                                                    │
│  Phase 2 – CORRELATE                                              │
│    └── Join findings → resource state → public IP binding         │
│                                                                    │
│  Phase 3 – CLASSIFY                                               │
│    └── Assign lifecycle bucket to each finding                    │
│                                                                    │
│  Phase 4 – FILTER                                                 │
│    └── Suppress STALE / GHOST; keep ACTIVE / DORMANT / ORPHANED  │
│                                                                    │
│  Phase 5 – OUTPUT                                                 │
│    ├── Regenerate dashboard/index.html                            │
│    ├── Write state/lifecycle_state.json                           │
│    └── Fire alerts for ACTIVE + ORPHANED (new findings only)      │
└──────────────────────────────────────────────────────────────────┘
```

---

## File Structure

```
Wiz/
├── ATTACK_SURFACE_LIFECYCLE_PLAYBOOK.md    ← this file
├── attack_surface_lifecycle.py             ← main script
├── config_lifecycle.yaml                   ← configuration
├── requirements.txt
├── dashboard/
│   ├── index.html                          ← generated each run
│   └── archive/                            ← suppressed findings log (NDJSON)
├── state/
│   └── lifecycle_state.json               ← persisted known IDs + history
└── logs/
    └── lifecycle.log
```

---

## Phase 1 — Collect

### Query A: Attack Surface Issues

Fetches all open issues whose entity is a **publicly reachable resource** (compute instances, load balancers, storage buckets with public access, serverless endpoints, managed databases with public endpoints).

```graphql
query AttackSurfaceIssues(
  $filterBy: IssueFilters
  $first: Int
  $after: String
) {
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
        externalId           # cloud-native resource ID (instance-id, etc.)
        type                 # VirtualMachine | LoadBalancer | StorageBucket | ...
        nativeType           # AWS::EC2::Instance | etc.
        name
        cloudPlatform        # AWS | Azure | GCP
        region
        subscriptionId
        subscriptionName
        publicIpAddress      # primary public IPv4
        publicDnsName
        ipAddresses          # all IPs (includes secondary, IPv6)
        status               # resource-level status from Wiz inventory
        tags
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

**Variables:**
```json
{
  "filterBy": {
    "status": ["OPEN", "IN_PROGRESS"],
    "severity": ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
    "entityType": [
      "VIRTUAL_MACHINE",
      "LOAD_BALANCER",
      "STORAGE_BUCKET",
      "MANAGED_DATABASE",
      "SERVERLESS",
      "KUBERNETES_SERVICE",
      "CONTAINER",
      "NETWORK_INTERFACE"
    ]
  },
  "first": 100
}
```

> **Note:** `entitySnapshot.status` reflects Wiz's last-known inventory state. Because Wiz scans are not real-time, Phase 2 cross-references this against cloud events to detect very recent terminations.

---

### Query B: Resource State (Instance / Service Inventory)

For each unique `entitySnapshot.externalId` collected in Query A, fetch the live Wiz inventory record to get the authoritative launch/run state.

```graphql
query ResourceState($filterBy: CloudResourceFilters, $first: Int, $after: String) {
  cloudResources(filterBy: $filterBy, first: $first, after: $after) {
    nodes {
      id
      externalId
      name
      type
      nativeType
      status               # RUNNING | STOPPED | TERMINATED | DELETED | UNKNOWN
      region
      cloudPlatform
      subscriptionId
      publicIpAddress
      ipAddresses
      tags
      lastSeenAt           # last time Wiz confirmed this resource exists
      createdAt
    }
    pageInfo { hasNextPage endCursor }
  }
}
```

**Variables:**
```json
{
  "filterBy": {
    "externalId": ["<list of externalIds from Query A>"]
  },
  "first": 100
}
```

**Status mapping across clouds:**

| Wiz status | AWS | Azure | GCP |
|---|---|---|---|
| `RUNNING` | running | VM running | RUNNING |
| `STOPPED` | stopped | VM deallocated | TERMINATED (GCP stopped) |
| `TERMINATED` | terminated | VM deleted | TERMINATED (fully deleted) |
| `DELETED` | (resource gone from API) | same | same |

---

### Query C: Cloud Events (Stop / Terminate / IP Release)

Captures very recent lifecycle events that may not yet be reflected in Wiz inventory (bridging the scan gap).

```graphql
query LifecycleCloudEvents(
  $filterBy: CloudEventFilters
  $first: Int
  $after: String
) {
  cloudEvents(filterBy: $filterBy, first: $first, after: $after) {
    nodes {
      id
      eventType
      eventTime
      cloudPlatform
      region
      subscriptionId
      errorCode            # non-empty means the action failed (skip for state updates)
      subject {
        id
        externalId         # matches entitySnapshot.externalId
        name
        type
      }
      actor {
        id
        name
        email
        type               # USER | SERVICE | ROLE
      }
      sourceIPAddress
    }
    pageInfo { hasNextPage endCursor }
  }
}
```

**Variables — event types to track:**
```json
{
  "filterBy": {
    "eventTime": { "after": "<now - 30 minutes>" },
    "eventType": [
      "StopInstances",
      "TerminateInstances",
      "DeleteVirtualMachine",
      "compute.instances.delete",
      "compute.instances.stop",
      "ReleaseAddress",
      "DisassociateAddress",
      "DeletePublicIpAddress",
      "DestroyInstance",
      "SetCommonInstanceMetadata"
    ]
  },
  "first": 500
}
```

> The 30-minute lookback on cloud events is intentionally longer than the 5-minute poll interval to catch events that arrive with CloudTrail delivery lag.

---

## Phase 2 — Correlate

For each finding from Query A, build a **CorrelatedFinding** object by joining:

```
CorrelatedFinding {
  finding            ← Query A node
  resource_state     ← Query B node matched on externalId (or None if not in inventory)
  recent_events      ← Query C events where subject.externalId == finding.entitySnapshot.externalId
  public_ip_active   ← bool (derived — see logic below)
}
```

### Public IP "still active" logic

An IP is considered **active** (still bound) when **all** of the following hold:

1. `resource_state.publicIpAddress` is not null/empty, **or** the IP appears in `resource_state.ipAddresses`.
2. No successful `ReleaseAddress` / `DisassociateAddress` cloud event exists for that IP in `recent_events`.
3. `resource_state.status` is not `TERMINATED` or `DELETED`.

An IP is considered **released** when **any** of the following hold:

- `resource_state` is `None` (resource no longer appears in Wiz inventory at all).
- `resource_state.status` is `TERMINATED` or `DELETED`.
- A successful `ReleaseAddress` or `DisassociateAddress` event exists for the IP in `recent_events` with no corresponding re-association after it.
- `resource_state.publicIpAddress` is null **and** the IP does not appear in `ipAddresses`.

> **Elastic IP edge case:** If an AWS Elastic IP was associated with the terminated instance, it may be re-associated with a new instance. The script checks whether the EIP is now bound to a *different* `externalId`. If so, it creates a new finding record for the new instance rather than suppressing.

---

## Phase 3 — Classify

Apply the lifecycle bucket rules in order:

```python
def classify(cf: CorrelatedFinding) -> LifecycleBucket:
    status = cf.resource_state.status if cf.resource_state else "DELETED"
    ip_active = cf.public_ip_active

    if status == "RUNNING" and ip_active:
        return ACTIVE_EXPOSURE

    if status == "STOPPED" and ip_active:
        return DORMANT_RISK

    if status == "STOPPED" and not ip_active:
        return STALE_FINDING        # suppress

    if status in ("TERMINATED", "DELETED") and not ip_active:
        return GHOST                # suppress

    if status in ("TERMINATED", "DELETED") and ip_active:
        return ORPHANED_IP          # EIP or reassignment — alert

    return STALE_FINDING            # fallback: suppress
```

---

## Phase 4 — Filter

| Bucket | Action | Dashboard | Alert |
|--------|--------|-----------|-------|
| `ACTIVE_EXPOSURE` | Keep | Yes — top section | Yes, if new & severity ≥ threshold |
| `DORMANT_RISK` | Keep | Yes — middle section | Warn only |
| `ORPHANED_IP` | Keep | Yes — highlighted | Yes, always (unexpected binding) |
| `STALE_FINDING` | Suppress | No | No — logged to archive/ |
| `GHOST` | Suppress | No | No — logged to archive/ |

Suppressed findings are **not discarded** — they are appended to `dashboard/archive/<date>.ndjson` with their classification reason, so the security team has a full audit trail.

---

## Phase 5 — Dashboard (index.html)

Self-contained HTML file, no server required. Regenerated every 5 minutes.

### Layout

```
┌─────────────────────────────────────────────────────────────┐
│  WIZ ATTACK SURFACE MONITOR  │  Last updated: 2026-05-07 … │
│  Accounts: 12  │  Regions: 8  │  Next poll: 4m 32s         │
└─────────────────────────────────────────────────────────────┘

┌── SUMMARY ──────────────────────────────────────────────────┐
│  🔴 ACTIVE EXPOSURE  │  🟠 DORMANT RISK  │  🟣 ORPHANED IP  │
│  CRITICAL: 2  HIGH: 7│  CRITICAL: 1 HIGH: 3│  1             │
│  MEDIUM: 12           │  MEDIUM: 8          │                │
│  Suppressed today: 34 ghost / 18 stale                       │
└─────────────────────────────────────────────────────────────┘

┌── ACTIVE EXPOSURES (instance RUNNING, public IP bound) ──────┐
│ Sev │ Instance ID     │ Public IP    │ Region  │ Control      │
│ ... │ ...             │ ...          │ ...     │ ...          │
└─────────────────────────────────────────────────────────────┘

┌── DORMANT RISKS (instance STOPPED, public IP still reserved) ┐
│ Sev │ Instance ID     │ Public IP    │ Region  │ Last Seen    │
└─────────────────────────────────────────────────────────────┘

┌── ORPHANED IPs (instance TERMINATED, IP still bound) ────────┐
│ Sev │ Original ID     │ Public IP    │ Now on  │ Wiz Finding  │
└─────────────────────────────────────────────────────────────┘

┌── TREND (24h) ───────────────────────────────────────────────┐
│  [Chart.js line chart: active / dormant / orphaned counts]   │
└─────────────────────────────────────────────────────────────┘
```

### Suppression transparency

A collapsible section shows today's suppressed count with a link to the archive NDJSON, so suppression is auditable without cluttering the main view.

---

## Alert Rules

### Rule 1 — New Active Exposure

**Trigger:** Finding classified as `ACTIVE_EXPOSURE` with severity `CRITICAL` or `HIGH` not present in `lifecycle_state.json` from the previous run.

**Payload includes:**
- Instance ID, public IP, cloud account, region
- Wiz control name + framework mapping
- Direct link: `https://app.wiz.io/issues/<finding_id>`

---

### Rule 2 — Orphaned IP Detected

**Trigger:** Any finding classified as `ORPHANED_IP`, regardless of severity or whether it was seen before (always re-alert until the IP is released or the finding is resolved).

**Payload includes:**
- Original terminated instance ID
- Public IP that is still bound
- New resource now holding the IP (if resolvable)
- Time since original instance termination

---

### Rule 3 — Stopped Instance with Reserved IP > Threshold

**Trigger:** Finding classified as `DORMANT_RISK` where `resource_state.status` has been `STOPPED` for more than `dormant_alert_hours` (default: 48h), meaning the IP has been unnecessarily reserved.

**Purpose:** Catches instances that were "temporarily" stopped but never cleaned up, leaving an attack surface that could be activated at any time.

---

### Rule 4 — Suppression Anomaly

**Trigger:** More than `suppression_spike_threshold` (default: 50) findings are suppressed in a single run. This could indicate a mass-termination event (intentional cleanup or incident) that warrants a heads-up.

---

## State File: lifecycle_state.json

```json
{
  "last_run_utc": "2026-05-07T10:00:00Z",
  "known_finding_ids": {
    "active": ["wiz-issue-id-1", "..."],
    "dormant": ["wiz-issue-id-2", "..."],
    "orphaned": ["wiz-issue-id-3", "..."]
  },
  "dormant_since": {
    "wiz-issue-id-2": "2026-05-05T08:00:00Z"
  },
  "history": [
    {
      "timestamp": "2026-05-07T10:00:00Z",
      "active_critical": 2,
      "active_high": 7,
      "active_medium": 12,
      "dormant": 12,
      "orphaned": 1,
      "suppressed_ghost": 34,
      "suppressed_stale": 18
    }
  ]
}
```

---

## Configuration (config_lifecycle.yaml)

```yaml
wiz:
  client_id: "${WIZ_CLIENT_ID}"
  client_secret: "${WIZ_CLIENT_SECRET}"
  api_endpoint: "https://api.us20.app.wiz.io/graphql"
  auth_url: "https://auth.app.wiz.io/oauth/token"
  audience: "wiz-api"

polling:
  interval_seconds: 300
  cloud_event_lookback_minutes: 30   # longer than interval to cover CloudTrail lag

filters:
  min_severity: "LOW"                # capture all, lifecycle bucketing decides what's shown
  instance_statuses_to_track:
    - "RUNNING"
    - "STOPPED"
    - "TERMINATED"
    - "DELETED"

lifecycle:
  dormant_alert_hours: 48            # alert on stopped instances with reserved IPs after 48h
  suppression_spike_threshold: 50    # alert if more than this many findings suppressed in one run
  recheck_suppressed_after_hours: 24 # re-evaluate suppressed findings every 24h in case IP is reused

alerts:
  trigger_on:
    - ACTIVE_EXPOSURE                # severities: CRITICAL, HIGH
    - ORPHANED_IP                    # all severities
    - DORMANT_RISK_AGED              # after dormant_alert_hours
    - SUPPRESSION_SPIKE
  slack:
    enabled: false
    webhook_url: "${SLACK_WEBHOOK_URL}"
  email:
    enabled: false
    smtp_host: "smtp.gmail.com"
    smtp_port: 587
    sender: "${EMAIL_SENDER}"
    password: "${EMAIL_PASSWORD}"
    recipients: ["security-team@example.com"]
  pagerduty:
    enabled: false
    integration_key: "${PAGERDUTY_INTEGRATION_KEY}"

dashboard:
  output_dir: "./dashboard"
  archive_dir: "./dashboard/archive"
  max_history_snapshots: 288         # 24 hours at 5-min intervals
```

---

## Scheduler Options

### System cron
```cron
*/5 * * * *  /usr/bin/python3 /path/to/Wiz/attack_surface_lifecycle.py >> /path/to/logs/lifecycle_cron.log 2>&1
```

### Daemon mode (Docker / long-running process)
```bash
python3 attack_surface_lifecycle.py --daemon
```

### Local development
```
/loop 5m python3 attack_surface_lifecycle.py
```

---

## Wiz API Permissions Required

| Scope | Purpose |
|-------|---------|
| `read:issues` | Query A — attack surface findings |
| `read:resources` | Query B — instance/service inventory state |
| `read:cloud_events` | Query C — stop/terminate/IP-release events |

Grant via: **Wiz Console → Settings → Service Accounts → Create → Reader role**.

---

## Quick Start

```bash
# 1. Install dependencies
pip install requests PyYAML APScheduler jinja2

# 2. Export credentials
export WIZ_CLIENT_ID="your-client-id"
export WIZ_CLIENT_SECRET="your-client-secret"

# 3. Set your regional API endpoint in config_lifecycle.yaml

# 4. Single test run
python3 attack_surface_lifecycle.py

# 5. Review dashboard
open dashboard/index.html

# 6. Start polling daemon
python3 attack_surface_lifecycle.py --daemon
```

---

## Key Differences from the General Playbook

| Aspect | General Playbook | This Playbook |
|--------|-----------------|---------------|
| Scope | All issue types | Attack surface only |
| Core filter | Severity + status | Instance lifecycle state + IP binding |
| Suppression | None (all open issues shown) | Terminates/stale IPs actively suppressed |
| Extra alert types | New CRITICAL/HIGH | Orphaned IPs, aged dormant, suppression spike |
| Archive | None | Suppressed findings logged to NDJSON per day |
| State tracked | Seen issue IDs | Seen IDs + dormant-since timestamps |
