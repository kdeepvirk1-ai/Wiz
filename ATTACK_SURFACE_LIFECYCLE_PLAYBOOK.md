# Wiz — External Attack Surface Monitoring (Resource Lifecycle Playbook)

## Problem Statement

Wiz attack surface findings remain open for resources that have since been **terminated, decommissioned, or deleted** and whose **public IPs or domains have been released**. This creates noise that buries real exposures. This playbook solves that by correlating every attack surface finding against the current lifecycle state of the underlying resource — regardless of whether that resource is a compute instance, container, load balancer, NAT gateway, or any other service with a public IP — then:

- **Suppressing** findings whose resource is terminated/decommissioned *and* whose public IP or domain is no longer bound to any active resource.
- **Flagging** findings whose resource is stopped/paused but whose IP is still reserved (dormant risk).
- **Escalating** findings whose resource is running with an active public exposure.
- **Alerting** on orphaned IPs where the original resource is gone but the IP has been rebound or not yet released.

The dashboard surfaces only actionable findings, grouped by lifecycle state and resource type.

---

## Covered Resource Types

Any cloud resource with a public IP address or publicly resolvable hostname is in scope:

Only resources that **directly serve application traffic to external users** are in scope. Infrastructure-only resources (NAT gateways, standalone public IPs, network interfaces, storage buckets, CDNs, managed databases) are excluded even if they have a public IP.

| Category | Resource Types | Examples |
|---|---|---|
| **Compute** | Virtual machines running application workloads | AWS EC2, Azure VM, GCP Compute Instance |
| **Containers** | Container tasks, pods, container groups serving app traffic | AWS ECS Task, EKS Pod, Azure Container Instance, GCP Cloud Run |
| **Load Balancers** | Application and network load balancers fronting external apps | AWS ALB/NLB/CLB, Azure LB, GCP LB |
| **Serverless** | Function endpoints and API gateways serving external requests | AWS Lambda URL, API Gateway, Azure Function, GCP Cloud Run |
| **Kubernetes Services** | NodePort / LoadBalancer-type services with external IPs | EKS, AKS, GKE services with external IPs |
| **API Management** | API proxies and gateways exposing external APIs | AWS API Gateway, Azure API Management, GCP Apigee |

---

## Core Concept: Lifecycle States

Every attack surface finding is classified into one of five lifecycle buckets before it reaches the dashboard. The classification applies uniformly across all resource types by first normalizing the resource's native status into a canonical state.

```
Finding
  │
  ├─ Resource ACTIVE    + Public IP/domain bound    →  ACTIVE EXPOSURE   (alert + show)
  │
  ├─ Resource INACTIVE  + Public IP/domain bound    →  DORMANT RISK      (warn + show)
  │
  ├─ Resource INACTIVE  + IP/domain released        →  STALE FINDING     (suppress + log)
  │
  ├─ Resource GONE      + IP/domain released        →  RESOLVED (GHOST)  (suppress + log)
  │
  └─ Resource GONE      + IP/domain still bound     →  ORPHANED IP       (alert + show)
       (Elastic IP / DNS record not cleaned up — a new resource may have inherited the exposure)
```

### Canonical Status Normalization

Native cloud statuses are mapped to four canonical states before classification:

| Canonical | AWS | Azure | GCP | Notes |
|---|---|---|---|---|
| `ACTIVE` | running, active, in-service, available | Running, Succeeded (LB) | RUNNING, READY | Resource is processing traffic |
| `INACTIVE` | stopped, stopping, paused, draining | Stopped, Deallocated | TERMINATED (GCP stopped), SUSPENDED | Resource exists but is not serving |
| `GONE` | terminated, deleted, shutting-down | Deleted, Deleting | TERMINATED (deleted) | Resource no longer exists in cloud API |
| `UNKNOWN` | Any other / missing from inventory | same | same | Treat conservatively — do not suppress |

**Container-specific normalization:**

| Native | Canonical | Notes |
|---|---|---|
| ECS: `RUNNING` | `ACTIVE` | Task is live |
| ECS: `STOPPED`, `DEPROVISIONED` | `GONE` | ECS tasks don't persist when stopped |
| K8s: `Running` | `ACTIVE` | Pod is ready |
| K8s: `Succeeded`, `Failed` | `GONE` | Terminal pod states — pod won't restart |
| K8s: `Terminating` | `INACTIVE` | Briefly; treat as GONE if IP already released |
| ACI / Cloud Run: `Running` | `ACTIVE` | |
| ACI / Cloud Run: `Terminated`, `Stopped` | `GONE` | Container groups don't persist when stopped |

**Load balancer-specific normalization:**

| Native | Canonical |
|---|---|
| AWS: `active`, `active_impaired` | `ACTIVE` |
| AWS: `provisioning` | `ACTIVE` (IP is bound during provisioning) |
| AWS: `failed`, `decommissioned` | `GONE` |
| Azure: `Succeeded` (running) | `ACTIVE` |
| Azure: `Deleting`, `Failed` | `GONE` |
| GCP: `RUNNING` | `ACTIVE` |

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
│    ├── Query A : Attack Surface Issues  (all public-IP resources) │
│    ├── Query B : Resource inventory state (all resource types)    │
│    └── Query C : Cloud Events  (lifecycle + IP release events)    │
│                                                                    │
│  Phase 2 – CORRELATE                                              │
│    └── Join findings → resource state → IP/domain binding         │
│                                                                    │
│  Phase 3 – NORMALIZE + CLASSIFY                                   │
│    ├── Map native status → canonical state (per resource type)    │
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

Fetches all open issues whose entity is a **publicly reachable resource** with an associated IP address or domain across all resource types.

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
        externalId           # cloud-native resource ID
        type                 # VirtualMachine | Container | LoadBalancer | ...
        nativeType           # AWS::EC2::Instance | AWS::ECS::Task | AWS::ElasticLoadBalancingV2::LoadBalancer | etc.
        name
        cloudPlatform        # AWS | Azure | GCP
        region
        subscriptionId
        subscriptionName
        publicIpAddress      # primary public IPv4
        publicDnsName        # public hostname / FQDN
        ipAddresses          # all IPs (includes secondary, IPv6, container IPs)
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
      "CONTAINER",
      "CONTAINER_GROUP",
      "LOAD_BALANCER",
      "SERVERLESS",
      "KUBERNETES_SERVICE",
      "API_MANAGEMENT"
    ],
    "hasPublicIP": true
  },
  "first": 100
}
```

> **Note:** `hasPublicIP: true` ensures only resources with an actual IP or domain are included. Resources that match entity type but have no public IP binding (e.g. internal-only load balancers) are excluded from collection.

---

### Query B: Resource State (All Resource Types)

For each unique `entitySnapshot.externalId` collected in Query A, fetch the live Wiz inventory record to get the authoritative lifecycle state and current IP binding. This query is resource-type agnostic — Wiz normalizes status across all cloud resource types.

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
      publicDnsName        # hostname/FQDN for LBs and services with DNS names
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

**Status mapping across resource types and clouds:**

| Wiz status | Meaning | Applies to |
|---|---|---|
| `RUNNING` | Resource is live and processing traffic | VMs, containers, LBs, managed DBs, serverless |
| `STOPPED` | Resource exists but is not serving (restorable) | VMs only — most other types skip directly to DELETED |
| `TERMINATED` | Resource has been decommissioned; IP may or may not be released | VMs, some LBs |
| `DELETED` | Resource no longer appears in cloud inventory API | All types |
| `UNKNOWN` | Wiz has not scanned recently; treat conservatively | All types |

> **Container note:** ECS tasks and container groups (ACI, Cloud Run) move directly from `RUNNING` to `DELETED` — there is no persistent stopped state. A missing inventory record for a container resource should be treated as `DELETED`, not `STOPPED`.

---

### Query C: Cloud Events (Lifecycle + IP Release)

Captures very recent lifecycle events that may not yet be reflected in Wiz inventory (bridging the scan gap). Covers all resource types.

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

**Variables — event types to track (grouped by resource type):**
```json
{
  "filterBy": {
    "eventTime": { "after": "<now - 30 minutes>" },
    "eventType": [
      "StopInstances",
      "TerminateInstances",
      "compute.instances.delete",
      "compute.instances.stop",
      "DeleteVirtualMachine",
      "DestroyInstance",

      "StopTask",
      "DeregisterTaskDefinition",
      "DeleteService",
      "Microsoft.ContainerInstance/containerGroups/delete",
      "google.cloud.run.v2.Services.DeleteService",

      "DeleteLoadBalancer",
      "DeregisterTargets",
      "Microsoft.Network/loadBalancers/delete",
      "compute.forwardingRules.delete",

      "DeleteRestApi",
      "DeleteStage",
      "Microsoft.ApiManagement/service/delete",
      "apigee.organizations.environments.delete",

      "ReleaseAddress",
      "DisassociateAddress",
      "DeletePublicIpAddress",
      "Microsoft.Network/publicIPAddresses/delete",
      "compute.addresses.delete",

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
  resource_type      ← normalized category: VM | CONTAINER | LOAD_BALANCER | NETWORK | OTHER
  resource_state     ← Query B node matched on externalId (or None if not in inventory)
  canonical_status   ← ACTIVE | INACTIVE | GONE | UNKNOWN  (derived from resource_type + native status)
  recent_events      ← Query C events where subject.externalId == finding.entitySnapshot.externalId
  public_ip_active   ← bool (derived — see logic below)
  public_dns_active  ← bool (derived — for resources with DNS names rather than bare IPs)
}
```

### Public IP / Domain "still active" logic

An IP or domain is considered **active** (still bound) when **all** of the following hold:

1. `resource_state.publicIpAddress` is not null/empty, **or** the IP appears in `resource_state.ipAddresses`, **or** `resource_state.publicDnsName` is not null/empty.
2. No successful `ReleaseAddress` / `DisassociateAddress` / `DeletePublicIpAddress` / equivalent cloud event exists for that IP in `recent_events`.
3. `canonical_status` is not `GONE`.

An IP or domain is considered **released** when **any** of the following hold:

- `resource_state` is `None` (resource no longer appears in Wiz inventory).
- `canonical_status` is `GONE`.
- A successful IP-release event exists for the IP in `recent_events` with no re-association after it.
- `resource_state.publicIpAddress` is null **and** the IP does not appear in `ipAddresses` **and** `publicDnsName` is null/empty.
- For load balancers and Kubernetes services: `resource_state` is `None` and no DNS record resolves to a live IP (checked via auxiliary DNS lookup step).

> **Elastic IP / Static IP edge case:** If an AWS Elastic IP or GCP static external IP was associated with the terminated resource, it may be re-associated with a new resource. The script checks whether the IP is now bound to a *different* `externalId`. If so, it creates a new finding record for the new resource rather than suppressing.

> **Load balancer DNS edge case:** ALB/NLB DNS names (e.g. `my-alb-1234.us-east-1.elb.amazonaws.com`) persist as DNS entries even after deletion during TTL expiry. The script treats an LB DNS name as released only if the LB resource is `GONE` **and** the DNS name no longer resolves (or resolves to a different resource).

---

## Phase 3 — Normalize + Classify

### Step 1: Normalize native status to canonical state

```python
def normalize_status(resource_type: str, native_status: str, resource_state) -> str:
    if resource_state is None:
        return "GONE"

    # Containers (ECS tasks, ACI groups, Cloud Run) have no persistent stopped state
    if resource_type == "CONTAINER":
        if native_status in ("RUNNING", "READY", "active"):
            return "ACTIVE"
        return "GONE"   # stopped/failed/deprovisioned containers are effectively gone

    # Load balancers
    if resource_type == "LOAD_BALANCER":
        if native_status in ("active", "active_impaired", "provisioning",
                              "RUNNING", "Succeeded"):
            return "ACTIVE"
        if native_status in ("failed", "decommissioned", "Deleting",
                              "Deleted", "TERMINATED", "DELETED"):
            return "GONE"
        return "UNKNOWN"

    # VMs and general resources
    STATUS_MAP = {
        "RUNNING":    "ACTIVE",
        "running":    "ACTIVE",
        "STOPPED":    "INACTIVE",
        "stopped":    "INACTIVE",
        "TERMINATED": "GONE",
        "DELETED":    "GONE",
        "UNKNOWN":    "UNKNOWN",
    }
    return STATUS_MAP.get(native_status, "UNKNOWN")
```

### Step 2: Classify into lifecycle bucket

```python
def classify(cf: CorrelatedFinding) -> LifecycleBucket:
    status = cf.canonical_status
    ip_active = cf.public_ip_active or cf.public_dns_active

    if status == "ACTIVE" and ip_active:
        return ACTIVE_EXPOSURE

    if status == "INACTIVE" and ip_active:
        return DORMANT_RISK

    if status == "INACTIVE" and not ip_active:
        return STALE_FINDING        # suppress

    if status == "GONE" and not ip_active:
        return GHOST                # suppress

    if status == "GONE" and ip_active:
        return ORPHANED_IP          # IP/DNS not cleaned up — alert

    if status == "UNKNOWN":
        return ACTIVE_EXPOSURE      # conservative: surface unknown resources

    return STALE_FINDING            # fallback: suppress
```

---

## Phase 4 — Filter

| Bucket | Action | Dashboard | Alert |
|--------|--------|-----------|-------|
| `ACTIVE_EXPOSURE` | Keep | Yes — top section | Yes, if new & severity ≥ threshold |
| `DORMANT_RISK` | Keep | Yes — middle section | Warn only |
| `ORPHANED_IP` | Keep | Yes — highlighted | Yes, always (unexpected binding) |
| `STALE_FINDING` | **Suppress** | **No — filtered out** | No — logged to archive/ |
| `GHOST` | **Suppress** | **No — filtered out** | No — logged to archive/ |

Suppressed findings are **not discarded** — they are appended to `dashboard/archive/<date>.ndjson` with their classification reason and the resource type, so the security team has a full audit trail.

### Filter criteria summary

A finding is removed from the dashboard when **both** conditions are true:
1. The resource's canonical status is `GONE` or `INACTIVE` (terminated, decommissioned, deleted, or container/task stopped).
2. The public IP address **and** public DNS name associated with the finding are no longer bound to any active resource.

If either condition is false (resource still exists OR IP/DNS is still live), the finding stays visible.

---

## Phase 5 — Dashboard (index.html)

Self-contained HTML file, no server required. Regenerated every 5 minutes.

### Layout

```
┌─────────────────────────────────────────────────────────────────────┐
│  WIZ ATTACK SURFACE MONITOR  │  Last updated: 2026-05-07 …          │
│  Accounts: 12  │  Regions: 8  │  Next poll: 4m 32s                  │
└─────────────────────────────────────────────────────────────────────┘

┌── SUMMARY ──────────────────────────────────────────────────────────┐
│  🔴 ACTIVE EXPOSURE   │  🟠 DORMANT RISK    │  🟣 ORPHANED IP        │
│  CRITICAL: 2  HIGH: 7 │  CRITICAL: 1 HIGH: 3│  1                    │
│  MEDIUM: 12           │  MEDIUM: 8          │                        │
│                                                                       │
│  BY TYPE: VM:8  Container:4  LoadBalancer:3  Network:2  Other:2      │
│  Suppressed today: 34 ghost / 18 stale  (filtered — IP released)     │
└─────────────────────────────────────────────────────────────────────┘

┌── ACTIVE EXPOSURES (resource ACTIVE, public IP/domain bound) ────────┐
│ Sev │ Type         │ Resource ID / Name  │ Public IP / DNS  │ Region  │
│ CRI │ VM           │ i-0abc123           │ 54.12.34.56      │ us-east │
│ HI  │ LoadBalancer │ my-alb-prod         │ my-alb.elb.a.com │ us-east │
│ HI  │ Container    │ task/api-service-1  │ 52.10.20.30      │ eu-west │
│ MED │ K8s Service  │ svc/payments-lb     │ 35.200.100.5     │ ap-east │
│ ... │ ...          │ ...                 │ ...              │ ...     │
└─────────────────────────────────────────────────────────────────────┘

┌── DORMANT RISKS (resource INACTIVE, public IP still reserved) ───────┐
│ Sev │ Type │ Resource ID / Name  │ Public IP     │ Inactive Since     │
└─────────────────────────────────────────────────────────────────────┘

┌── ORPHANED IPs (resource GONE, IP/domain still bound) ───────────────┐
│ Sev │ Type │ Original Resource   │ IP / DNS      │ Now Bound To       │
└─────────────────────────────────────────────────────────────────────┘

┌── FILTERED / SUPPRESSED ─────────────────────────────────────────────┐
│  [Collapsed by default — click to expand]                             │
│  Shows count of suppressed findings with reason:                      │
│    • GHOST (resource gone + IP released): 34                          │
│    • STALE (resource inactive + IP released): 18                      │
│  Download full audit log: archive/2026-05-07.ndjson                  │
└─────────────────────────────────────────────────────────────────────┘

┌── TREND (24h) ───────────────────────────────────────────────────────┐
│  [Chart.js line chart: active / dormant / orphaned counts by type]   │
└─────────────────────────────────────────────────────────────────────┘
```

### Dashboard filter behavior

- Findings in `GHOST` or `STALE_FINDING` buckets are **never rendered in the main table rows**; they appear only in the collapsed suppression summary section.
- The suppression section shows the count, reason, resource type breakdown, and a link to the archive log for auditability.
- Refreshing or re-running the script will automatically remove any row whose underlying resource has since been terminated and whose IP has been released — no manual intervention required.

---

## Alert Rules

### Rule 1 — New Active Exposure

**Trigger:** Finding classified as `ACTIVE_EXPOSURE` with severity `CRITICAL` or `HIGH` not present in `lifecycle_state.json` from the previous run.

**Payload includes:**
- Resource type, resource ID/name, public IP, public DNS name
- Cloud account, region
- Wiz control name + framework mapping
- Direct link: `https://app.wiz.io/issues/<finding_id>`

---

### Rule 2 — Orphaned IP or DNS Detected

**Trigger:** Any finding classified as `ORPHANED_IP`, regardless of severity or whether it was seen before (always re-alert until the IP/domain is released or the finding is resolved).

**Payload includes:**
- Resource type and original resource ID
- Public IP or DNS name that is still bound
- New resource now holding the IP/DNS (if resolvable)
- Time since original resource termination/deletion

---

### Rule 3 — Inactive Resource with Reserved IP > Threshold

**Trigger:** Finding classified as `DORMANT_RISK` where canonical status has been `INACTIVE` for more than `dormant_alert_hours` (default: 48h).

**Note:** This rule applies primarily to VMs. Containers and load balancers that are stopped are normalized to `GONE`, so they will be classified as `GHOST` (suppressed) or `ORPHANED_IP` (alerted) rather than `DORMANT_RISK`.

---

### Rule 4 — Suppression Anomaly

**Trigger:** More than `suppression_spike_threshold` (default: 50) findings are suppressed in a single run. This could indicate a mass-decommission event (intentional cleanup or incident) that warrants a heads-up.

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
      "suppressed_stale": 18,
      "by_resource_type": {
        "VM": { "active": 8, "dormant": 5, "orphaned": 0, "suppressed": 20 },
        "CONTAINER": { "active": 4, "dormant": 0, "orphaned": 1, "suppressed": 8 },
        "LOAD_BALANCER": { "active": 3, "dormant": 2, "orphaned": 0, "suppressed": 10 },
        "NETWORK": { "active": 2, "dormant": 5, "orphaned": 0, "suppressed": 14 },
        "OTHER": { "active": 2, "dormant": 0, "orphaned": 0, "suppressed": 0 }
      }
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
  cloud_event_lookback_minutes: 30   # longer than interval to cover CloudTrail delivery lag

filters:
  min_severity: "LOW"                # capture all; lifecycle bucketing decides what's shown
  require_public_ip: true            # only track resources with a public IP or DNS name
  resource_types:
    - "VIRTUAL_MACHINE"
    - "CONTAINER"
    - "CONTAINER_GROUP"
    - "LOAD_BALANCER"
    - "SERVERLESS"
    - "KUBERNETES_SERVICE"
    - "API_MANAGEMENT"

lifecycle:
  dormant_alert_hours: 48            # alert on stopped VMs with reserved IPs after 48h
  suppression_spike_threshold: 50    # alert if more than this many findings suppressed in one run
  recheck_suppressed_after_hours: 24 # re-evaluate suppressed findings every 24h in case IP is reused
  dns_ttl_grace_minutes: 10          # extra window before treating a deleted LB DNS name as released

alerts:
  trigger_on:
    - ACTIVE_EXPOSURE                # severities: CRITICAL, HIGH
    - ORPHANED_IP                    # all severities, all resource types
    - DORMANT_RISK_AGED              # after dormant_alert_hours (VMs only)
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
  show_suppressed_section: true      # collapsed section showing filtered-out count
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
| `read:resources` | Query B — inventory state for all resource types |
| `read:cloud_events` | Query C — lifecycle and IP-release events |

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

## Key Differences from the Original Instance-Only Playbook

| Aspect | Instance-Only | This Playbook |
|--------|--------------|---------------|
| Scope | EC2/VM instances only | All resource types with a public IP or DNS |
| Resource types | 1 (VirtualMachine) | 7 app-hosting types (VM, Container, LB, Serverless, K8s Service, API Management) |
| Status normalization | Direct AWS status mapping | Per-type canonical normalization before classification |
| Container handling | Not covered | ECS tasks / pods normalized directly to GONE when stopped |
| Load balancer DNS | Not covered | DNS TTL grace period before treating LB hostname as released |
| Dashboard columns | Instance ID + IP | Resource type + resource ID/name + IP or DNS |
| Suppression trigger | Instance terminated + IP released | Any resource type decommissioned + IP/DNS released |
| State history | Flat counts | Counts broken down by resource type |
