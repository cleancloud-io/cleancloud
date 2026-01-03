# CleanCloud Design & Positioning

CleanCloud is intentionally positioned **between noisy hygiene alerts and risky automation**.

It exists to answer one question safely:

> What cloud resources look abandoned enough to review — without risking production?

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

**CleanCloud sits in the "trust zone" between:**
- Native cloud services (too noisy/shallow for actionable hygiene)
- Automation tools (too risky for production environments)

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

## What CleanCloud Is Not

- Not a cost optimization tool
- Not an automated cleanup engine
- Not a replacement for Config, TA, or policies
- Not a dashboard that flags everything

CleanCloud is a **hygiene intelligence layer** focused on safety and trust.
