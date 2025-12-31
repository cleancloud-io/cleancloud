# CleanCloud Safety & Read-Only Guarantees

CleanCloud is designed with a **trust-first, enterprise-ready approach**. This document describes the **multi-layer safety regression tests** that ensure CleanCloud **never mutates cloud resources** during scans.

---

## Table of Contents

1. [Introduction](#introduction)
2. [Folder Structure](#folder-structure)
3. [AWS Safety Regression Tests](#aws-safety-regression-tests)
    - [Static AST Test](#static-ast-test)
    - [Runtime SDK Guard](#runtime-sdk-guard)
    - [IAM Policy Test](#iam-policy-test)
4. [Azure Safety Regression Tests](#azure-safety-regression-tests)
    - [Static AST Test](#static-ast-test-1)
    - [Runtime SDK Guard](#runtime-sdk-guard-1)
    - [Role Definition Test](#role-definition-test)
5. [Adding New Rules Safely](#adding-new-rules-safely)
6. [CI Integration](#ci-integration)

---

## Introduction

CleanCloud provides **provable read-only safety** for both AWS and Azure through **three layers of safety checks**:

1. **Static AST checks** — Detect forbidden SDK calls in provider code.
2. **Runtime SDK guards** — Intercept any forbidden calls during test execution.
3. **Policy / Role definition tests** — Ensure IAM policies (AWS) and RBAC roles (Azure) grant only read-only permissions.

These tests run automatically in CI and are **required for all PRs**.

---

## Folder Structure
```
cleancloud/
├── safety/
│ ├── aws/
│ │ ├── init.py
│ │ ├── allowlist.py
│ │ ├── test_static_readonly.py
│ │ ├── runtime_guard.py
│ │ └── test_iam_policy_readonly.py
│ └── azure/
│ ├── init.py
│ ├── allowlist.py
│ ├── test_static_readonly.py
│ ├── runtime_guard.py
│ └── test_role_definition_readonly.py
├── security/
│ ├── aws-readonly-policy.json
│ └── azure-readonly-role.json
```

- **`safety/`** → all static + runtime + policy/role tests
- **`security/`** → canonical AWS IAM policy and Azure role definition

---

## AWS Safety Regression Tests

### Static AST Test

- File: `cleancloud/safety/aws/test_static_readonly.py`
- Purpose: Scan provider code to **ensure no forbidden mutating API calls** exist.
- Uses: `allowlist.py` to define forbidden prefixes (`Delete*`, `Put*`, `Update*`, `Create*`)
- Failure: Any forbidden call raises an `AssertionError` in CI.

### Runtime SDK Guard

- File: `cleancloud/safety/aws/runtime_guard.py`
- Purpose: Intercept **runtime calls** to AWS SDK (`boto3`) during tests.
- Mechanism: `pytest` autouse fixture wraps clients; any mutating method call raises an exception.
- Dummy test included to ensure pytest module execution.

### IAM Policy Test

- File: `cleancloud/safety/aws/test_iam_policy_readonly.py`
- Purpose: Ensure `aws-readonly-policy.json` grants **read-only permissions only**.
- Checks: No `Delete*`, `Put*`, `Update*`, `Create*` actions.
- CI failure occurs if policy grants unsafe actions.

---

## Azure Safety Regression Tests

### Static AST Test

- File: `cleancloud/safety/azure/test_static_readonly.py`
- Purpose: Scan Azure provider code for forbidden SDK calls (`delete`, `begin_delete`, `create`, `begin_create`, `update`, `begin_update`).
- Failure: Assertion error if a forbidden call exists in code.

### Runtime SDK Guard

- File: `cleancloud/safety/azure/runtime_guard.py`
- Purpose: Intercept any forbidden Azure SDK calls at runtime.
- Mechanism: Autouse fixture wraps Azure client instances (`ComputeManagementClient`, `StorageManagementClient`, etc.)
- Dummy test ensures pytest executes the module.

### Role Definition Test

- File: `cleancloud/safety/azure/test_role_definition_readonly.py`
- Purpose: Validate `azure-readonly-role.json` is read-only.
- Forbidden actions: `*/delete`, `*/write`, `*/create`, `*/update`
- Any violation fails the test.

---

## Adding New Rules Safely

1. **Check SDK calls** → Only use `list*`, `get*`, or other read-only operations.
2. **Update allowlist** → Add new read-only methods if necessary.
3. **Run static AST test** → Ensure no forbidden methods appear.
4. **Run runtime tests** → Ensure no forbidden method is called at runtime.
5. **Update policy / role JSON** → Only if new permissions are required.
6. **Run CI** → Safety regression tests must pass before merge.

---

### Developer CI (CleanCloud Repo)

All safety regression tests for AWS and Azure are included in the **main test suite**:

```yaml
- name: Run tests
  run: |
    pytest tests/ -v --cov=cleancloud --cov-report=xml
```

* Running this single job is sufficient; **no separate jobs for AWS/Azure safety tests** are required.
* Any failure in safety regression tests will **fail the CI build**, preventing unsafe merges.

## Summary

CleanCloud’s **multi-layer safety regression** ensures:

* **No cloud resource mutation** during scans
* **Provable read-only enforcement** via AST, runtime, and policy/role tests
* **Enterprise-ready trust** for SRE teams and auditors

All safety tests are **required for CI** and fully documented in this repository for transparency and audit purposes.