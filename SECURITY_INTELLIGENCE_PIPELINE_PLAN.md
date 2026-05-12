# Security Intelligence Pipeline — Plan & Tool Guide

> **Plain-English Summary:**  
> Think of this as building a security command centre. Right now Wiz tells you *something might be wrong*, but it doesn't know whether the exposed service is still live, whether the vulnerability is actually reachable from the internet, or whether its "Critical" label is really warranted. This plan connects Wiz findings, your real traffic logs from Coralogix, live cloud IP data, and Claude AI to answer one question: **"Of all these findings, which ones are genuinely dangerous right now?"** Everything is displayed on a single dashboard and stored for auditing and trending.

---

## The Five Big Steps at a Glance

```
┌─────────────────────────────────────────────────────────────────────┐
│  STEP 1 │  Pull findings from Wiz + pull traffic logs from Coralogix│
├─────────────────────────────────────────────────────────────────────┤
│  STEP 2 │  Check: is the public IP still live on that service?       │
├─────────────────────────────────────────────────────────────────────┤
│  STEP 3 │  Check: is the vulnerable port/service actually reachable? │
├─────────────────────────────────────────────────────────────────────┤
│  STEP 4 │  Ask Claude AI: is Wiz's severity score actually correct?  │
├─────────────────────────────────────────────────────────────────────┤
│  STEP 5 │  Show everything on one dashboard + store for audit trail  │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Step 1 — Pull the Data

### 1A: Pull findings from Wiz

**What you get:** Every open security issue Wiz has found — misconfigurations, exposed ports, unpatched software — along with the resource (VM, container, load balancer, etc.) it was found on and the public IP attached to it.

**How:** Wiz exposes a GraphQL API. You send it a query and it returns a JSON list of findings. This is already documented in detail in [ATTACK_SURFACE_LIFECYCLE_PLAYBOOK.md](ATTACK_SURFACE_LIFECYCLE_PLAYBOOK.md).

**Tools:**
| Tool | What it does |
|---|---|
| `requests` (Python library) | Sends the HTTP request to the Wiz API |
| Wiz GraphQL endpoint | `https://api.us20.app.wiz.io/graphql` (region-specific) |
| Wiz service account | Needs `read:issues`, `read:resources`, `read:cloud_events` scopes |

**Key fields to capture from Wiz:**
- Finding ID, severity (CRITICAL / HIGH / MEDIUM / LOW), control name
- Resource type, resource ID, public IP address, public DNS name
- Finding status (OPEN / IN_PROGRESS), created date
- CVE IDs if present, CVSS score if present

---

### 1B: Pull traffic logs from Coralogix

**What you get:** Real network/application logs that show whether the public IP is actively receiving traffic — and from where.

**Why this matters:** Wiz might flag a service as "exposed to the internet," but if Coralogix shows zero inbound traffic to that IP in the last 30 days, the practical risk is much lower than one receiving thousands of requests per hour.

**How:** Coralogix has a REST query API. You send it a time-range and a filter (e.g. destination IP = the IPs from Wiz findings), and it returns matching log lines.

**Tools:**
| Tool | What it does |
|---|---|
| Coralogix DataPrime API | Query logs using Coralogix's query language |
| Coralogix REST Logs API | `POST https://<region>.coralogix.com/api/v1/dataprime/query` |
| Coralogix API Key | Generated in Coralogix → Data Flow → API Keys → Logs Query key |
| `requests` (Python) | Sends the query |

**Example Coralogix query (DataPrime syntax):**
```
source logs
| filter $d.destination_ip == '54.12.34.56'
| filter $m.timestamp > startOfHour(-720)   // last 30 days
| groupby [$d.destination_ip, $d.destination_port]
  aggregate count() as request_count
```

**Key fields to capture from Coralogix:**
- Destination IP and port (matches the Wiz finding's public IP)
- Source IP / country (where traffic is coming from)
- Request volume over last 7 / 30 days
- Any error codes, unusual patterns, or known bad-actor IPs

---

## Step 2 — Verify the Public IP Is Still Live

**The problem this solves:** Wiz's inventory can be hours or days behind reality. A service might have been terminated yesterday, but Wiz still shows it as exposed. Before doing anything else, confirm the IP is still bound to an active resource.

**How:** Ask the cloud provider directly using its own API.

**Tools by cloud:**

| Cloud | Tool / SDK | What to call |
|---|---|---|
| AWS | `boto3` (Python AWS SDK) | `ec2.describe_addresses()` for Elastic IPs; `elbv2.describe_load_balancers()` for ALBs |
| Azure | `azure-mgmt-network` (Python SDK) | `public_ip_addresses.get()` |
| GCP | `google-cloud-compute` (Python SDK) | `addresses().list()` |

**Decision logic (plain English):**
```
If the cloud API says the IP is still attached to a running resource → proceed to Step 3
If the cloud API says the IP is released / the resource is gone → mark as SUPPRESSED (no further action, log it)
```

This is the same filtering logic defined in the lifecycle playbook — Step 2 here is running it in real time against cloud APIs, not just Wiz's cached inventory.

---

## Step 3 — Confirm the Vulnerable Service Is Actually Reachable

**The problem this solves:** Just because a public IP exists doesn't mean the specific vulnerable port or service is open to the internet. A security group or firewall rule might already be blocking it.

**How:** For each finding where the IP is confirmed live, perform a lightweight reachability check on the specific port the finding refers to.

**Tools:**
| Tool | What it does |
|---|---|
| `socket` / `nmap` (Python) | Tests if a specific TCP port is open and responding |
| Shodan API | Queries Shodan's internet-wide scan database — tells you what the world can see on that IP without you actively scanning |
| Censys API | Same idea as Shodan — passive internet scan data |

> **Shodan/Censys are preferred** for production use because they don't generate active scan traffic (which can trigger alerts or be mistaken for an attack).

**Decision logic:**
```
If port is confirmed reachable from internet → mark as EXPOSED (proceed to Step 4)
If port is blocked / not responding → mark as SHIELDED (lower priority, still log it)
```

---

## Step 4 — Claude AI Severity Validation

**The problem this solves:** Wiz assigns severity (Critical, High, Medium, Low) based on configuration rules and CVSS scores. But it doesn't know context: Is the service behind a WAF? Does the vulnerability require authentication? Is there real traffic hitting it? This step sends all that context to Claude and asks: "Based on everything we know, is this finding actually as severe as Wiz says?"

**How it works:**
1. For each finding that passed Steps 2 and 3 (IP live + service reachable), build a prompt that includes:
   - The Wiz finding details (control name, CVE, CVSS, description)
   - The Coralogix traffic data (request volume, source countries, anomalies)
   - The IP validation result (confirmed live, resource type)
   - The reachability result (port open, service banner if available)
2. Send it to Claude via the Anthropic API.
3. Claude returns a structured assessment.

**Tools:**
| Tool | What it does |
|---|---|
| Anthropic Python SDK (`anthropic`) | Sends prompts to Claude and receives responses |
| Claude model | `claude-opus-4-7` for highest accuracy on complex security reasoning |
| Prompt template | See below |

**Example Claude prompt structure:**
```
You are a senior cloud security engineer performing a risk validation review.

FINDING:
- Control: {control_name}
- Description: {description}
- Wiz Severity: {severity}
- CVE: {cve_id}  CVSS Score: {cvss_score}
- Exploitability (CVSS): {exploitability_subscores}

EXPOSURE CONTEXT:
- Resource type: {resource_type}  Cloud: {cloud}  Region: {region}
- Public IP: {public_ip}  Confirmed live: {ip_live}
- Port {port} reachable from internet: {port_open}
- Shodan/Censys data: {shodan_summary}

TRAFFIC DATA (last 30 days from Coralogix):
- Total inbound requests: {request_count}
- Unique source IPs: {unique_sources}
- Known malicious IPs in traffic: {malicious_ip_count}
- Traffic trend: {trend}

TASK:
1. Validate whether Wiz's severity of "{severity}" is accurate given the actual exposure.
2. Assign a VALIDATED_SEVERITY: CRITICAL | HIGH | MEDIUM | LOW | INFORMATIONAL
3. Explain your reasoning in 2-3 sentences.
4. State the primary exploitation scenario if exploited.
5. Recommend the single most impactful remediation step.

Respond in JSON.
```

**Claude's output (JSON):**
```json
{
  "validated_severity": "HIGH",
  "wiz_severity": "CRITICAL",
  "severity_change": "DOWNGRADED",
  "reasoning": "While the CVE has a CVSS of 9.8, Coralogix shows no inbound traffic to this IP in 30 days and Shodan shows port 22 is not responding. The theoretical risk is critical but practical exposure is very low.",
  "primary_exploitation_scenario": "Remote code execution via unauthenticated SSH if port becomes accessible.",
  "recommended_action": "Verify security group rule blocking port 22 is still in place and add monitoring alert if it is removed."
}
```

---

## Step 5 — Dashboard + Storage

### 5A: The Dashboard

**What it shows:**
- All confirmed, live, reachable findings — grouped by validated severity (not just Wiz's label)
- Side-by-side comparison: Wiz severity vs. Claude-validated severity (so you can see where Wiz over- or under-called)
- Findings broken down by: resource type, cloud account, region, service
- Traffic volume per exposed service (from Coralogix)
- Suppressed findings count (terminated resources / released IPs)
- Trend chart: how the number of real exposures has changed over the last 7/30 days

**Layout:**
```
┌──────────────────────────────────────────────────────────────────────┐
│  SECURITY INTELLIGENCE DASHBOARD         Last updated: 2026-05-11    │
│  Validated findings: 23 │ Suppressed (IP gone): 41 │ Shielded: 12   │
└──────────────────────────────────────────────────────────────────────┘

┌── SEVERITY SUMMARY ──────────────────────────────────────────────────┐
│  VALIDATED CRITICAL: 2   VALIDATED HIGH: 8   MEDIUM: 9   LOW: 4      │
│  Wiz said CRITICAL: 12  →  Claude confirmed: 2  (10 downgraded)      │
└──────────────────────────────────────────────────────────────────────┘

┌── CONFIRMED LIVE EXPOSURES ──────────────────────────────────────────┐
│ Val.Sev │ Wiz Sev │ Type       │ Resource       │ IP/DNS    │ Traffic │
│ CRIT    │ CRIT    │ VM         │ i-0abc123      │ 54.x.x.x  │ 12k/day │
│ HIGH    │ CRIT    │ LoadBalancer│ my-alb-prod   │ my-alb.…  │  8k/day │
│ HIGH    │ HIGH    │ Container  │ task/api-svc-1 │ 52.x.x.x  │  3k/day │
└──────────────────────────────────────────────────────────────────────┘

┌── BY SERVICE TYPE ───────────────────────────────────────────────────┐
│  VM: 8  │  Container: 6  │  LoadBalancer: 5  │  Serverless: 4       │
└──────────────────────────────────────────────────────────────────────┘

┌── SEVERITY CORRECTION RATE ──────────────────────────────────────────┐
│  [Bar chart: Wiz CRITICAL=12, Claude CRITICAL=2, HIGH=8, MED=2]      │
└──────────────────────────────────────────────────────────────────────┘

┌── TREND (7 days) ────────────────────────────────────────────────────┐
│  [Line chart: confirmed exposures by day]                             │
└──────────────────────────────────────────────────────────────────────┘
```

**Tools for the dashboard:**
| Tool | What it does |
|---|---|
| `jinja2` (Python) | Generates the HTML file from a template |
| Chart.js (JavaScript) | Renders bar and line charts in the browser |
| Self-contained HTML | No server needed — open with any browser |
| Grafana (optional) | If your team prefers a hosted dashboard, connect it to the storage layer |

---

### 5B: Storage — Do You Need It?

**Yes, you need storage.** Here is why:
1. **Trending:** To show whether your security posture is improving over time, you need to compare today's findings against last week's.
2. **Audit trail:** If an incident happens, you need to prove what was known, when, and what action was taken.
3. **Claude cost control:** Re-running Claude on the same unchanged finding every 5 minutes is wasteful. Store the Claude assessment and only re-validate when the finding changes.
4. **Coralogix cost control:** Querying 30 days of logs on every poll is expensive. Cache the traffic summaries.

---

### Storage Options

#### Option A — AWS (Recommended if your cloud is AWS)

```
┌─────────────────────────────────────────────────────────────────────┐
│                         AWS STORAGE STACK                            │
│                                                                       │
│  Raw findings + logs (cold)                                           │
│  ┌──────────────────────────────────────────────┐                   │
│  │  Amazon S3                                    │                   │
│  │  • Raw Wiz API responses (JSON)               │                   │
│  │  • Coralogix log exports (NDJSON)             │                   │
│  │  • Claude AI responses (JSON)                 │                   │
│  │  • Dashboard HTML archives                    │                   │
│  │  Cost: ~$0.023/GB/month                       │                   │
│  └──────────────────────────────────────────────┘                   │
│                                                                       │
│  Structured findings (hot — queried every poll)                       │
│  ┌──────────────────────────────────────────────┐                   │
│  │  Amazon DynamoDB                              │                   │
│  │  • Current finding state per resource         │                   │
│  │  • Validated severity history per finding     │                   │
│  │  • IP binding state cache                     │                   │
│  │  Cost: pay-per-request, very low at this scale│                   │
│  └──────────────────────────────────────────────┘                   │
│                                                                       │
│  Log search + alerting (optional)                                     │
│  ┌──────────────────────────────────────────────┐                   │
│  │  Amazon OpenSearch Service                    │                   │
│  │  • Full-text search across all findings       │                   │
│  │  • Kibana-style dashboard (built-in)          │                   │
│  │  • Grafana connector available                │                   │
│  │  Cost: ~$0.10/GB ingested                     │                   │
│  └──────────────────────────────────────────────┘                   │
└─────────────────────────────────────────────────────────────────────┘
```

**Recommended minimal AWS setup:** S3 + DynamoDB. OpenSearch only if you want to enable ad-hoc searching across all historical findings.

---

#### Option B — Azure (Recommended if your cloud is Azure)

```
┌─────────────────────────────────────────────────────────────────────┐
│                        AZURE STORAGE STACK                           │
│                                                                       │
│  Raw findings + logs (cold)                                           │
│  ┌──────────────────────────────────────────────┐                   │
│  │  Azure Blob Storage                           │                   │
│  │  • Same raw data as S3 above                  │                   │
│  │  Cost: ~$0.018/GB/month (LRS)                 │                   │
│  └──────────────────────────────────────────────┘                   │
│                                                                       │
│  Structured findings (hot)                                            │
│  ┌──────────────────────────────────────────────┐                   │
│  │  Azure Cosmos DB (NoSQL API)                  │                   │
│  │  • Same purpose as DynamoDB                   │                   │
│  │  Cost: pay-per-RU (request unit)              │                   │
│  └──────────────────────────────────────────────┘                   │
│                                                                       │
│  Log search + dashboards (optional)                                   │
│  ┌──────────────────────────────────────────────┐                   │
│  │  Azure Monitor + Log Analytics Workspace      │                   │
│  │  • Built-in KQL query language                │                   │
│  │  • Native Azure Workbook dashboards           │                   │
│  │  • Connects to Grafana                        │                   │
│  │  Cost: ~$2.76/GB ingested                     │                   │
│  └──────────────────────────────────────────────┘                   │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Complete Data Flow (End to End)

```
Every 5 minutes:

  Wiz API ──────────────────────────────────────┐
                                                 │
  Coralogix API ───────────────────────────────→ STEP 1: Collect
                                                 │
                                                 ▼
                                          STEP 2: Is the IP still live?
                                          (AWS Boto3 / Azure SDK / GCP SDK)
                                                 │
                                    ┌────────────┴────────────┐
                                  No: IP                    Yes: IP
                                  released                  still live
                                    │                          │
                               SUPPRESS                  STEP 3: Is the port open?
                               + log to S3          (Shodan / Censys / socket check)
                                                          │
                                             ┌────────────┴────────────┐
                                           No: port                 Yes: port
                                           blocked                  reachable
                                             │                          │
                                        SHIELDED                  STEP 4: Claude AI
                                        (log it,                  severity validation
                                        lower priority)           (Anthropic SDK)
                                                                       │
                                                                  STEP 5: Write results
                                                                  to DynamoDB / Cosmos DB
                                                                  + archive to S3 / Blob
                                                                       │
                                                                  Regenerate dashboard
                                                                  (index.html)
```

---

## Python Libraries You Will Need

```
# Wiz + Coralogix API calls
requests

# AWS storage + cloud SDK
boto3

# Azure storage + cloud SDK
azure-mgmt-network
azure-mgmt-compute
azure-storage-blob
azure-cosmos

# GCP SDK (if needed)
google-cloud-compute

# Claude AI
anthropic

# Dashboard generation
jinja2

# Scheduling
APScheduler

# Config
PyYAML

# Optional: passive reachability checks
shodan      # requires a Shodan API key
censys      # requires a Censys API key
```

Install all at once:
```bash
pip install requests boto3 azure-mgmt-network azure-mgmt-compute \
    azure-storage-blob azure-cosmos google-cloud-compute \
    anthropic jinja2 APScheduler PyYAML shodan censys
```

---

## Environment Variables / Secrets Needed

```bash
# Wiz
WIZ_CLIENT_ID=
WIZ_CLIENT_SECRET=

# Coralogix
CORALOGIX_API_KEY=
CORALOGIX_REGION=         # e.g. EU1, US1, AP1 (from your Coralogix account)

# Claude AI
ANTHROPIC_API_KEY=

# AWS (if using AWS storage)
AWS_ACCESS_KEY_ID=
AWS_SECRET_ACCESS_KEY=
AWS_REGION=
S3_BUCKET_NAME=
DYNAMODB_TABLE_NAME=

# Azure (if using Azure storage)
AZURE_SUBSCRIPTION_ID=
AZURE_TENANT_ID=
AZURE_CLIENT_ID=
AZURE_CLIENT_SECRET=
COSMOS_DB_ENDPOINT=
COSMOS_DB_KEY=
BLOB_CONNECTION_STRING=

# Shodan / Censys (optional)
SHODAN_API_KEY=
CENSYS_API_ID=
CENSYS_API_SECRET=
```

---

## New Files This Plan Introduces

```
Wiz/
├── ATTACK_SURFACE_LIFECYCLE_PLAYBOOK.md     ← existing (lifecycle + suppression logic)
├── SECURITY_INTELLIGENCE_PIPELINE_PLAN.md   ← this file (the plan)
│
├── pipeline/
│   ├── collect_wiz.py          ← Step 1A: Wiz GraphQL queries
│   ├── collect_coralogix.py    ← Step 1B: Coralogix log queries
│   ├── validate_ip.py          ← Step 2: Cloud SDK IP checks
│   ├── check_reachability.py   ← Step 3: Shodan/Censys/socket checks
│   ├── claude_validator.py     ← Step 4: Claude AI severity validation
│   ├── storage.py              ← Step 5A: DynamoDB / Cosmos DB read/write
│   └── main.py                 ← Orchestrates all steps, generates dashboard
│
├── templates/
│   └── dashboard.html.j2       ← Jinja2 dashboard template
│
├── dashboard/
│   ├── index.html              ← Generated output
│   └── archive/                ← Historical snapshots + suppressed log
│
└── state/
    └── pipeline_state.json     ← Tracks last-seen finding IDs + Claude cache
```

---

## Quick Start Sequence

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Copy and fill in your secrets
cp .env.example .env
# Edit .env with your API keys

# 3. Run a single test pass (no daemon)
python3 pipeline/main.py --once

# 4. Review the dashboard
open dashboard/index.html

# 5. Check what Claude said about each finding
cat state/pipeline_state.json | python3 -m json.tool | grep validated_severity

# 6. Start the recurring daemon (every 5 minutes)
python3 pipeline/main.py --daemon
```

---

## Cost Estimates (Rough Monthly, Small-to-Medium Environment)

| Component | Service | Est. Monthly Cost |
|---|---|---|
| Wiz API calls | Included in Wiz subscription | $0 |
| Coralogix log queries | ~1000 queries/month at standard plan | ~$0–$50 |
| Claude AI validation | ~500 findings/day × $0.003/finding (Opus) | ~$45 |
| AWS S3 (raw storage) | ~10 GB/month | ~$0.25 |
| AWS DynamoDB | ~1M reads/writes per month | ~$1.50 |
| AWS OpenSearch (optional) | 1 node t3.small.search | ~$50 |
| Shodan API (optional) | Freelancer plan | ~$59/mo |

**Total without OpenSearch/Shodan: ~$50–100/month**

> Claude cost scales with number of unique findings validated per day. Caching Claude assessments in DynamoDB and only re-running when a finding changes reduces this significantly.

---

## Summary: What Each Tool Does

| Tool | Role |
|---|---|
| **Wiz GraphQL API** | Source of truth for what vulnerabilities exist and on which resources |
| **Coralogix DataPrime API** | Source of truth for real inbound traffic to each exposed IP |
| **AWS Boto3 / Azure SDK** | Confirms in real time whether the cloud provider still has that IP bound to an active resource |
| **Shodan / Censys API** | Passively confirms what ports/services the internet can actually see on that IP |
| **Anthropic SDK (Claude)** | Interprets all of the above and gives a human-quality severity verdict with reasoning |
| **DynamoDB / Cosmos DB** | Stores current finding state, Claude verdicts, and history for trending |
| **S3 / Blob Storage** | Archives all raw data for audit and replay |
| **Jinja2 + Chart.js** | Generates the dashboard HTML from the processed data |
