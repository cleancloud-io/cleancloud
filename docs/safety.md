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

CleanCloud provides **provable read-only safety** for AWS, Azure, and GCP through **three layers of safety checks**:

1. **Static AST checks** — Detect forbidden SDK calls in provider code.
2. **Runtime SDK guards** — Intercept any forbidden calls during test execution.
3. **Policy / Role definition tests** — Ensure IAM policies (AWS) and RBAC roles (Azure) grant only read-only permissions.

These tests run automatically in CI and are **required for all PRs**.

---

## Folder Structure
```
cleancloud/
├── cleancloud/safety/              # Allowlists (read-only method definitions)
│   ├── aws/
│   │   ├── __init__.py
│   │   └── allowlist.py
│   ├── azure/
│   │   ├── __init__.py
│   │   └── allowlist.py
│   └── gcp/
│       ├── __init__.py
│       └── allowlist.py
├── tests/cleancloud/safety/        # Safety regression tests
│   ├── aws/
│   │   ├── test_aws_static_readonly.py
│   │   ├── test_aws_runtime_readonly.py
│   │   └── test_aws_iam_policy_readonly.py
│   ├── azure/
│   │   ├── test_azure_static_readonly.py
│   │   ├── test_azure_runtime_readonly.py
│   │   └── test_azure_role_definition_readonly.py
│   └── gcp/
│       ├── test_gcp_static_readonly.py
│       └── test_gcp_runtime_readonly.py
├── security/                       # Canonical IAM policies and role definitions
│   ├── aws-readonly-policy.json
│   ├── azure-readonly-role.json
│   ├── verify-aws-policy.sh
│   └── verify-azure-role.sh
```

- **`cleancloud/safety/`** → allowlists defining permitted read-only SDK methods
- **`tests/cleancloud/safety/`** → static, runtime, and policy/role safety tests
- **`security/`** → canonical AWS IAM policy, Azure role definition, and verification scripts

---

## AWS Safety Regression Tests

### Static AST Test

- File: `tests/cleancloud/safety/aws/test_aws_static_readonly.py`
- Purpose: Scan provider code to **ensure no forbidden mutating API calls** exist.
- Uses: `cleancloud/safety/aws/allowlist.py` to define forbidden prefixes (`Delete*`, `Put*`, `Update*`, `Create*`)
- Failure: Any forbidden call raises an `AssertionError` in CI.

### Runtime SDK Guard

- File: `tests/cleancloud/safety/aws/test_aws_runtime_readonly.py`
- Purpose: Intercept **runtime calls** to AWS SDK (`boto3`) during tests.
- Mechanism: `pytest` autouse fixture wraps clients; any mutating method call raises an exception.

### IAM Policy Test

- File: `tests/cleancloud/safety/aws/test_aws_iam_policy_readonly.py`
- Purpose: Ensure `security/aws-readonly-policy.json` grants **read-only permissions only**.
- Checks: No `Delete*`, `Put*`, `Update*`, `Create*` actions.
- CI failure occurs if policy grants unsafe actions.

---

## Azure Safety Regression Tests

### Static AST Test

- File: `tests/cleancloud/safety/azure/test_azure_static_readonly.py`
- Purpose: Scan Azure provider code for forbidden SDK calls (`delete`, `begin_delete`, `create`, `begin_create`, `update`, `begin_update`).
- Uses: `cleancloud/safety/azure/allowlist.py` to define permitted read-only methods.
- Failure: Assertion error if a forbidden call exists in code.

### Runtime SDK Guard

- File: `tests/cleancloud/safety/azure/test_azure_runtime_readonly.py`
- Purpose: Intercept any forbidden Azure SDK calls at runtime.
- Mechanism: Autouse fixture wraps Azure client instances (`ComputeManagementClient`, `NetworkManagementClient`, etc.)

### Role Definition Test

- File: `tests/cleancloud/safety/azure/test_azure_role_definition_readonly.py`
- Purpose: Validate `security/azure-readonly-role.json` is read-only.
- Forbidden actions: `*/delete`, `*/write`, `*/create`, `*/update`
- Any violation fails the test.

---

## GCP Safety Regression Tests

### Static AST Test

- File: `tests/cleancloud/safety/gcp/test_gcp_static_readonly.py`
- Purpose: Scan GCP provider code for forbidden SDK method calls (`delete`, `insert`, `patch`, `update`, `set_*`, `add_*`, `remove_*`, `reset_*`, `start`, `stop`, `restart`, `create`).
- Uses: `cleancloud/safety/gcp/allowlist.py` to define the forbidden method prefix list.
- Failure: Assertion error if any forbidden method name appears in the AST of any provider file.
- Note: Python built-in method names that collide (e.g. `list.insert`, `dict.update`) are excluded by the helper `_is_forbidden()` function.

### Runtime SDK Guard

- File: `tests/cleancloud/safety/gcp/test_gcp_runtime_readonly.py`
- Purpose: Intercept runtime calls to GCP SDK clients (`compute_v1.DisksClient`, `InstancesClient`, `AddressesClient`, etc.) and block any attempt to access a mutating method.
- Mechanism: A `GuardedMock` subclass raises `ForbiddenGcpCallError` when a forbidden prefix is accessed.
- Confirms: Read-only methods (`aggregated_list`, `list`, `get`) remain accessible; mutating methods (`delete`, `stop`, `insert`) are blocked.

Note: GCP does not use a canonical customer-managed IAM policy JSON file (permissions are managed at the project/folder/org level using predefined roles), so there is no equivalent to the AWS IAM policy test. Instead, required permissions are documented in [`docs/gcp.md`](gcp.md).

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

* **No cloud resource mutation** during scans — across AWS, Azure, and GCP
* **Provable read-only enforcement** via AST, runtime, and policy/role tests
* **Enterprise-ready trust** for SRE teams and auditors

All safety tests are **required for CI** and fully documented in this repository for transparency and audit purposes.