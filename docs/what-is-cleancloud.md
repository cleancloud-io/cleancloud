# CleanCloud

**Category:** Cloud Hygiene Intelligence  
**Stage:** Early product, enterprise-grade foundations  
**Philosophy:** Read-only • Conservative • Trust-first

---

## What Is CleanCloud?

CleanCloud is a **cloud hygiene intelligence layer** that identifies **orphaned, unowned, and potentially inactive cloud resources** using **high-confidence, review-only signals**.

It does **not** automate cleanup.  
It tells teams **what deserves review — and why**.

---

## The Problem

Modern cloud environments are:
- Elastic and ephemeral
- Heavily IaC-driven
- Owned by many teams with weak attribution

This creates:
- Orphaned storage, snapshots, logs, and network resources
- Security and operational risk
- Cleanup paralysis due to blast-radius fear

### Why Existing Tools Fall Short
- **Auto-delete tools** → unsafe in production
- **Cost tools** → noisy, billing-centric, low trust
- **Security tools** → too broad, hygiene is a side concern

---

## CleanCloud’s Insight

> **Cloud hygiene is a trust problem, not an automation problem.**

Teams want:
- Conservative detection
- Transparent reasoning
- Explicit confidence levels
- Zero write permissions

CleanCloud is designed to earn trust first.

---

## What CleanCloud Does

- Scans AWS and Azure using **read-only APIs**
- Uses **multiple conservative signals per rule**
- Assigns explicit **confidence levels** (LOW / MEDIUM / HIGH)
- Preserves evidence for every finding
- Runs natively in CI/CD via **OIDC (no long-lived secrets)**

---

## What CleanCloud Deliberately Does NOT Do

- ❌ No auto-delete or auto-remediation
- ❌ No write, tag, or mutate permissions
- ❌ No billing or cost data access
- ❌ No opinionated workflows

This is a **strategic design choice**, not a limitation.

---

## Why CleanCloud Is Valuable

| Dimension | CleanCloud |
|--------|-----------|
| Safety | Read-only, review-only |
| Signal quality | Conservative, multi-signal rules |
| Trust | Explicit confidence + evidence |
| Adoption | CI-native, OIDC-first |
| Compliance | SOC2 / ISO / regulated-friendly |
| Integration | Clean JSON/CSV output |

---

## Users & Buyers

- **Primary users:** SRE, Platform, Infrastructure teams
- **Stakeholders:** Security, Compliance, FinOps

---

## Strategic Fit for an Acquirer

CleanCloud acts as:
- A **signal generator** upstream of automation
- A **trust layer** before remediation
- A **complement** to observability, security, and governance platforms

It is designed to be:
- Embedded
- Integrated
- Extended

—not replaced.

---

## Current State (v0.3.0)

- AWS + Azure support
- OIDC-first authentication (no secrets)
- Agentless, read-only scanning
- Conservative hygiene rules (storage, snapshots, logs, public IPs)
- CI/CD-ready doctor validation

---

## Near-Term Expansion (Low Risk)

- Ownership & attribution hints
- Rule contracts and evidence schemas
- Additional conservative hygiene rules

No change to the trust or safety model.

---

## Long-Term Vision

CleanCloud becomes the **standard cloud hygiene intelligence substrate** inside:
- Observability platforms
- CNAPP / security tooling
- CMDB and workflow engines

Always focused on **signal quality, trust, and safety**.

---

## Positioning Summary

CleanCloud is not a cleanup tool.

It is the **missing intelligence layer** that makes cleanup, governance, and automation safe to do *later* — by humans or trusted systems.
