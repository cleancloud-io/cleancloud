# Contributing to CleanCloud

Thank you for your interest in CleanCloud! We welcome contributions from the community.

---

## About the Project

CleanCloud is a **trust-first cloud hygiene engine** designed for production and enterprise environments. It provides read-only, confidence-scored hygiene signals for AWS, Azure, and GCP that are safe to run in production and CI/CD pipelines.

**Key Focus Areas:**
- **Read-only by design** - No mutations, deletions, or modifications
- **Enterprise-ready** - OIDC authentication, policy enforcement, audit-friendly
- **Conservative signals** - Explicit confidence levels (LOW/MEDIUM/HIGH)
- **Production-safe** - Multi-layer safety regression tests

**If you use CleanCloud:**
- Star the project to help signal adoption and guide investment
- Share feedback in [GitHub Discussions](https://github.com/cleancloud-io/cleancloud/discussions)
- For business inquiries (partnerships, licensing, integrations): suresh@getcleancloud.com

---

## How to Contribute

### Types of Contributions Welcome

**Bug Reports** - Found an issue? Let us know.

**Rule Proposals** - Suggest new hygiene rules (see Rule Addition Criteria below)

**Documentation Improvements** - Fix typos, clarify instructions, add examples

**Code Contributions** - Bug fixes, performance improvements, new rules

**Cloud Provider Support** - Help add GCP, OCI, or other cloud platforms

---

## Getting Started

### 1. Fork and Clone

```bash
git clone https://github.com/your-username/cleancloud.git
cd cleancloud
```

### 2. Set Up Development Environment

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -e .
pip install -r requirements-dev.txt  # If exists
```

### 3. Run Tests

```bash
pytest tests/
```

### 4. Make Your Changes

Create a feature branch:
```bash
git checkout -b feature/my-contribution
```

---

## Contribution Guidelines

### Code Style

- Follow PEP 8 for Python code
- Use type hints where appropriate
- Keep functions focused and single-purpose
- Add docstrings to all public functions

### Testing Requirements

All contributions must include tests:

**For bug fixes:**
- Add a test that reproduces the bug
- Verify the test passes after your fix

**For new rules:**
- Add unit tests for rule logic
- Mock cloud API responses (no real API calls in tests)
- Test all confidence levels (LOW, MEDIUM, HIGH)
- Test edge cases (empty results, missing fields)

**For new features:**
- Add integration tests if applicable
- Update documentation

### Documentation Requirements

All code changes must include documentation updates:

- Update relevant docs in `docs/` directory
- Add examples for new features
- Update README.md if user-facing changes
- Add entry to CHANGELOG.md (if exists)

---

## Rule Addition Criteria

CleanCloud has strict criteria for new hygiene rules to maintain trust and quality.

### A new rule must meet ALL of:

**1. Read-only operations only**
- No `Delete*`, `Modify*`, `Tag*`, or `Update*` API calls
- Safe to run in production environments

**2. Clear, measurable signals**
- No ambiguous heuristics
- Multiple signals preferred over single indicators
- Age-based thresholds for resources created by automation

**3. Explicit confidence levels**
- Must assign LOW, MEDIUM, or HIGH confidence
- Confidence criteria must be clearly documented
- HIGH confidence must have very low false positive rate

**4. Broadly applicable**
- Applies to most organizations (not niche use cases)
- Addresses common pain points
- Provides clear value (time/cost savings)

**5. Conservative by design**
- Prefer false negatives over false positives
- Account for IaC and autoscaling patterns
- Include "why this is safe" documentation

### Rule Proposal Process

1. **Open an issue** with the `rule-proposal` label
2. **Describe the problem** - What resources are orphaned? How common is this?
3. **Explain detection logic** - What signals would you use? What thresholds?
4. **Justify confidence levels** - Why is this HIGH vs MEDIUM vs LOW confidence?
5. **Address edge cases** - When might this produce false positives?
6. **Wait for maintainer feedback** - Rule proposals require approval before implementation

**Example rule proposal template:**
```
**Rule name:** Unused AWS Elastic IPs

**Problem:** Elastic IPs cost $0.005/hour when not attached, accumulating ~$3.65/month per IP

**Detection signals:**
- EIP allocation exists
- EIP not associated with instance or network interface
- Age > 7 days (to avoid catching IPs in deployment)

**Confidence:** HIGH (attachment state is deterministic)

**Edge cases:** 
- Reserved IPs for future use (mitigated by requiring tags to indicate "reserved")
- IPs being used for DNS records (can't detect, requires manual review)

**Required permissions:** ec2:DescribeAddresses
```

---

## Pull Request Process

### Before Submitting

- All tests pass locally
- Code follows style guidelines
- Documentation updated
- Commit messages are clear and descriptive

### PR Guidelines

**Title format:**
```
[Type] Brief description

Examples:
[Fix] Handle missing tags in Azure disk detection
[Feature] Add support for unused AWS Elastic IPs
[Docs] Clarify IAM policy requirements for AWS
```

**Description must include:**
- What problem does this solve?
- How was it tested?
- Any breaking changes?
- Screenshots (if UI/output changes)

### Review Process

1. Maintainer will review within 48 hours (best effort)
2. Address any feedback or requested changes
3. Once approved, maintainer will merge

---

## Code of Conduct

### Our Standards

**Be respectful and constructive:**
- Welcome newcomers and help them contribute
- Provide constructive feedback on PRs
- Focus on the code, not the person

**Focus on value:**
- Prioritize features that benefit many users
- Keep discussions technical and on-topic
- Respect maintainer decisions on scope

**Unacceptable behavior:**
- Harassment or discriminatory language
- Trolling or insulting comments
- Publishing private information

### Enforcement

Violations will result in:
1. Warning
2. Temporary ban
3. Permanent ban

**Report violations to:** suresh@getcleancloud.com or via private message to repository maintainers

---

## Development Tips

### Running CleanCloud Locally

**Set up credentials first:**

```bash
# AWS - using environment variables
export AWS_ACCESS_KEY_ID=<your-access-key>
export AWS_SECRET_ACCESS_KEY=<your-secret-key>
export AWS_DEFAULT_REGION=us-east-1

# Azure - using service principal
export AZURE_CLIENT_ID=<your-client-id>
export AZURE_TENANT_ID=<your-tenant-id>
export AZURE_CLIENT_SECRET=<your-client-secret>
export AZURE_SUBSCRIPTION_ID=<your-subscription-id>
```

**Run scans:**

```bash
# AWS scan
python -m cleancloud.cli scan --provider aws --region us-east-1

# Azure scan
python -m cleancloud.cli scan --provider azure
```

> **Note:** AWS CLI profiles and Azure CLI (`az login`) are also supported. See [docs/aws.md](docs/aws.md) and [docs/azure.md](docs/azure.md) for all authentication methods.

### Debugging

```bash
# Add verbose logging (if implemented)
cleancloud scan --provider aws --verbose

# Or use Python debugger
python -m pdb -m cleancloud.cli scan --provider aws
```

### Testing New Rules

```bash
# Test single rule file
pytest tests/providers/aws/rules/test_my_new_rule.py -v

# Test with real credentials (use test account!)
# Set up test account credentials first
export AWS_ACCESS_KEY_ID=<test-account-key>
export AWS_SECRET_ACCESS_KEY=<test-account-secret>

cleancloud scan --provider aws --region us-east-1
```

> **Warning:** Always use a dedicated test account for development. Never test against production.

---

## Community and Support

**Questions?**
- Open a GitHub issue with the `question` label
- Check existing documentation first

**Feature discussions?**
- Open a GitHub issue with the `enhancement` label
- Explain your use case and proposed solution

**Security issues?**
- Do NOT open a public issue
- Email: suresh@getcleancloud.com (subject: "Security Issue")
- We'll respond within 48 hours

---

## License

By contributing to CleanCloud, you agree that your contributions will be licensed under the MIT License.

All contributions must be your original work or properly attributed.

---

## Recognition

Contributors will be:
- Mentioned in release notes for their contributions
- Credited in documentation for significant features
- Listed in CONTRIBUTORS.md (for substantial contributions)
- Referenced for enterprise features on our website (with permission)

**We value all contributions** - whether it's fixing a typo, improving documentation, or adding a major feature. Every contribution helps make CleanCloud better for enterprise teams worldwide.

Thank you for helping make CleanCloud better!