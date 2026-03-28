# CleanCloud Design & Positioning

CleanCloud is the safest way to detect cloud waste in production — without risking outages or requiring write permissions.

It exists to answer one question safely:

> What orphaned resources are costing us money — without risking production?

---

## Why This Matters

Cloud waste is often invisible:

- Native tools (AWS Trusted Advisor, Azure Advisor) raise noisy, shallow alerts that miss cross-service signals
- Automation tools can delete IaC-managed resources, cause outages, and require elevated permissions that security teams won't approve
- SaaS FinOps platforms are off-limits for regulated industries (FSI, healthcare, government) due to data residency and compliance requirements
- Teams need a safe middle ground: deep detection with zero mutation risk, that runs inside their own environment

CleanCloud fills that gap. It requires only read access, produces actionable findings with explicit confidence levels, and can scan a single account or an entire AWS Organization / Azure tenant / GCP project fleet in one run — so teams can make informed decisions without fear.

---

## Where CleanCloud Fits
```
                         ┌──────────────────────────────┐
                         │     Native Cloud Services    │
                         │   (Config / TA / Policies)   │
                         │                              │
                         │   • Binary alerts            │
                         │   • Service-specific         │
                         │   • Account / org scoped     │
                         └───────────────▲──────────────┘
                                         │
                                         │
          Noisy / Shallow                │               Automated / Risky
                                         │
─────────────────────────────────────────┼─────────────────────────────────────────
                                         │
                                         │
                         ┌───────────────┴──────────────┐
                         │          CleanCloud          │
                         │                              │
                         │   • Read-only                │
                         │   • Review-only findings     │
                         │   • Multiple conservative    │
                         │     signals                  │
                         │   • Explicit confidence      │
                         │     levels (H/M/L)           │
                         │   • IaC-aware                │
                         │   • CI-friendly              │
                         │                              │
                         │ "Safe to review, never act"  │
                         └───────────────▲──────────────┘
                                         │
                                         │
                         ┌───────────────┴──────────────┐
                         │    Cleanup / Automation Tools│
                         │                              │
                         │   • Auto-delete              │
                         │   • Rightsizing              │
                         │   • Cost-driven actions      │
                         │   • Mutation by default      │
                         └──────────────────────────────┘
```
---

**CleanCloud sits in the "trust zone":**
- Cost optimization through safe, read-only hygiene detection
- Unlike native cloud services (too noisy/shallow) or automation tools (too risky for production)

| | Native Tools | CleanCloud | Automation Tools |
|---|---|---|---|
| Noise | High | Low | Medium |
| Mutation risk | None | **None** | High |
| Detection depth | Shallow | Deep | Deep |
| IaC-aware | No | **Yes** | No |
| CI/CD-friendly | Weak | **Strong** | Weak |
| Requires write access | No | **No** | Yes |
| Human review required | No | **Yes** | No |

## Design Principles

### 1. Review-Only by Design
CleanCloud never modifies, deletes, or tags resources.
All findings are **candidates for human review**, not automated action.

### 2. Conservative Signals
Each rule combines multiple signals (state, age, attachment, usage metadata)
to avoid false positives in IaC-driven environments.

### 3. Explicit Confidence
Findings are classified as LOW / MEDIUM / HIGH confidence
to support safe decision-making in production.

### 4. IaC-Aware
CleanCloud assumes infrastructure is ephemeral, declarative,
and frequently recreated — not manually curated.

---

## Why Read-Only Matters

Read-only isn't a limitation — it's a deliberate design choice:

- **No blast radius** — a misconfigured scan cannot delete or modify anything
- **No IaC conflicts** — resources managed by Terraform, CDK, or Pulumi are safe
- **Easy security approval** — ReadOnly/Reader roles clear most security reviews without escalation
- **Production-safe** — run against live accounts without risk of service disruption
- **Auditability** — every API call is a read; nothing in CloudTrail looks suspicious

This is why CleanCloud can be trusted in environments where automation tools cannot.

---

## Multi-Account, Multi-Subscription, and Multi-Project Scanning

CleanCloud scans entire AWS Organizations, Azure tenants, and GCP project fleets in a single run — not just individual accounts.

**AWS:**
- `--org` — auto-discover all accounts in the AWS Organization
- `--multi-account accounts.yaml` — scan a defined list of accounts via cross-account IAM roles
- `--accounts 111,222,333` — inline account list

**Azure:**
- Omit `--subscription` — scans all subscriptions the identity has Reader on
- `--management-group <ID>` — auto-discover all subscriptions under a Management Group

**GCP:**
- `--all-projects` — auto-discover all accessible ACTIVE projects via Resource Manager API
- `--project <ID>` — scan one or more specific projects (repeatable flag)

Findings from all accounts/subscriptions/projects are aggregated into a single report with a per-account breakdown and combined cost estimate. GCP uses Application Default Credentials with no hub-and-spoke complexity — the identity needs `roles/compute.viewer` and related read-only roles at the project level.

---

## Who This Is For

| Persona | Why CleanCloud helps |
|---|---|
| **Platform teams** | Enforce cloud hygiene standards across AWS Orgs and Azure tenants with scheduled governance scans |
| **FinOps practitioners** | Quantify waste with deterministic cost estimates and track trends over time |
| **SREs** | Catch orphaned resources before they cause cost surprises or config drift |
| **Security teams** | Approve and run read-only tooling without elevated permission risk |
| **Regulated industries** | Run inside your own environment — no data leaves your cloud account, no SaaS dependency |
| **MSPs** | Scan multiple customer accounts in a single run with per-account cost breakdowns |

---

## What CleanCloud Is Not

- Not an automated cleanup engine (one-click account nuking)
- Not a rightsizing or instance optimization tool
- Not a spending analysis dashboard
- Not a replacement for Config, TA, or policies

CleanCloud is a **cost optimization tool** built on safe, read-only hygiene evaluation.
