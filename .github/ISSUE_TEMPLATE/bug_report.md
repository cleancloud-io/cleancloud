---
name: Bug report
about: Report a bug in CleanCloud
title: '[BUG] '
labels: 'bug'
assignees: ''

---

## Bug Description

A clear description of what the bug is.

## Environment

**CleanCloud version:**
```bash
cleancloud --version
# Or: pip show cleancloud
```

**Python version:**
```bash
python --version
```

**Operating System:**
- [ ] macOS
- [ ] Linux (which distro: _______)
- [ ] Windows
- [ ] WSL

**Cloud Provider:**
- [ ] AWS
- [ ] Azure
- [ ] GCP
- [ ] Multiple

## Command Run
```bash
# Paste the exact command you ran
cleancloud scan --provider aws --region us-east-1
```

## Expected Behavior

What you expected to happen.

## Actual Behavior

What actually happened.

## Error Output
```
# Paste full error message / stack trace here
# Include the entire output, not just the error line
```

## Additional Context

**Auth configuration:**
- [ ] AWS — OIDC (AssumeRoleWithWebIdentity)
- [ ] AWS — profile / environment variables
- [ ] Azure — OIDC (Workload Identity)
- [ ] Azure — CLI / managed identity
- [ ] GCP — Workload Identity Federation
- [ ] GCP — gcloud ADC (local)
- [ ] GCP — service account key

**IAM Permissions:**
- [ ] I've run `cleancloud doctor --provider [aws/azure/gcp]`
- [ ] Doctor output: (paste if relevant)

**Scope:**
- Scanning specific region/project: _______
- Using `--all-regions` / `--all-projects`: Yes / No
- Number of AWS accounts / Azure subscriptions / GCP projects: _______

**Config file:**
- [ ] Using cleancloud.yaml
- [ ] Using custom config file
- [ ] No config file
```yaml
# If using config, paste relevant sections here (remove secrets!)
```

**Other context:**
- Running in CI/CD: Yes / No
- Behind corporate proxy: Yes / No
- Using VPN: Yes / No

## Reproducibility

- [ ] Happens every time
- [ ] Happens sometimes
- [ ] Happened once

## Workaround

If you found a workaround, please share it here.