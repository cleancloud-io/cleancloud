# CleanCloud Rules

46 rules across three providers (30 hygiene + 16 AI/ML).

| Provider | Hygiene | AI/ML | Total | Catalog |
|---|---|---|---|---|
| AWS | 13 | 6 | 19 | [rules/aws.md](rules/aws.md) |
| Azure | 12 | 5 | 17 | [rules/azure.md](rules/azure.md) |
| GCP | 5 | 5 | 10 | [rules/gcp.md](rules/gcp.md) |

**Information hierarchy:**
- `docs/rules/<provider>.md` — operator catalog: permissions, params, exclusions, spec links
- `docs/specs/<provider>/<rule>.md` — canonical decision contracts, evidence shape, cost model, failure behavior
- Rule `.py` header — implementation notes for engineers

---

## Design Principles

- **Read-only always** — no Delete, Modify, Tag, or Update operations; safe for production
- **Conservative by default** — multiple signals preferred; false negatives over false positives
- **Explicit confidence** — every finding carries HIGH / MEDIUM / LOW confidence
- **Review-only** — findings are candidates for human review, not triggers for automated action
