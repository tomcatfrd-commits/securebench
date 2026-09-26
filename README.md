# SecureBench

SecureBench is a modular security benchmark automation platform for auditing,
planning, remediating, verifying, and rolling back security controls across
heterogeneous systems.

The project is designed primarily for production environments where systems
already provide business services and security changes must be applied
carefully.

## Goals

SecureBench is intended to:

- Audit systems against multiple security benchmarks.
- Support CIS and other benchmark types without coupling the core engine to a
  specific benchmark.
- Separate benchmark requirements from remediation policy.
- Provide configurable profiles for different environments.
- Classify controls according to their remediation safety.
- Generate a remediation plan before making changes.
- Execute approved remediations through Ansible.
- Verify the resulting system state.
- Record every remediation as a transaction.
- Support control-level and transaction-level rollback.
- Preserve evidence before and after remediation.
- Be modular and extensible as new operating systems and benchmarks are added.

## Safety Model

SecureBench does not assume that every failed benchmark control should be
automatically remediated.

A control can be classified by a profile as, for example:

- `safe`
- `safe_with_precheck`
- `investigate`
- `approval_required`
- `prohibited`

The benchmark defines the security requirement.

The profile defines what SecureBench is allowed to do with that requirement.

The policy engine makes the final execution decision.

This separation is intentional because a benchmark control can be technically
valid while still being inappropriate to apply automatically to a particular
production workload.

## High-Level Architecture

```text
                    SecureBench
                         |
        +----------------+----------------+
        |                |                |
   Benchmarks         Profiles        Inventory
        |                |                |
        +----------------+----------------+
                         |
                   Policy Engine
                         |
                    Audit Engine
                         |
                Remediation Planner
                         |
                   Execution Engine
                         |
                      Ansible
                         |
                      Hosts
                         |
                   Verification
                         |
              +----------+----------+
              |                     |
             PASS                  FAIL
              |                     |
            Commit               Rollback
```
Python provides the application and control plane.

Ansible provides the initial execution backend.

The core application should not depend directly on CIS-specific logic or
Ansible-specific implementation details.

## Project Structure
```
securebench/
|
├── pyproject.toml
├── README.md
|
├── src/
│   └── securebench/
│       ├── cli/
│       ├── core/
│       ├── policy/
│       ├── audit/
│       ├── remediation/
│       ├── rollback/
│       ├── verification/
│       ├── execution/
│       └── reporting/
|
├── benchmarks/
│   ├── cis/
│   │   ├── ubuntu/
│   │   │   └── 24.04/
│   │   └── rhel/
│   ├── stig/
│   └── custom/
|
├── profiles/
│   ├── production-safe.yml
│   ├── production-review.yml
│   ├── aggressive.yml
│   └── custom.yml
|
├── ansible/
│   ├── roles/
│   ├── playbooks/
│   └── collections/
|
├── tests/
│   ├── unit/
│   ├── integration/
│   └── safety/
|
└── data/
    ├── transactions/
    ├── evidence/
    └── snapshots/
```
## Design Principles
### 1. Audit before remediation

Audit operations must not modify the target system.
```
audit
  |
  v
evidence
```
### 2. Plan before execution

SecureBench should be able to determine what it intends to change without
actually changing the target.
```
audit
  |
  v
policy
  |
  v
plan
```
### 3. Explicit safety classification

A failed control must not automatically imply permission to remediate it.
```
Benchmark requirement
        |
        v
Profile classification
        |
        v
Policy decision
```
### 4. Every change must be attributable

A remediation should be associated with:

- `benchmark`
- `control`
- `host`
- `profile`
- `transaction`
- `previous state`
- `requested state`
- `execution result`
- `verification result`
- `rollback information`

### 5. Verification is independent from remediation

A successful Ansible task does not necessarily prove that the security
requirement is satisfied.

The resulting state must be independently verified.

### 6. Rollback is part of remediation

Rollback information must be prepared before a change is made whenever the
control supports rollback.
```
prepare rollback
       |
       v
remediate
       |
       v
verify
       |
   +---+---+
   |       |
 PASS     FAIL
   |       |
 commit  rollback
 ```
### 7. Never claim universal rollback

Some changes cannot be reliably reconstructed.

Every control must explicitly describe its rollback capability.

Possible states include:
```
guaranteed
best_effort
unsupported
```

### 8. Benchmark-independent core

The core engine should not contain logic such as:
```
if benchmark == "CIS":
```
CIS should be implemented as benchmark data and control definitions.

The same engine should eventually support:
```
CIS
STIG
NIST-derived controls
PCI-derived controls
internal security baselines
custom benchmarks
```
### Initial Target
```
The first implementation target is:

Ubuntu Server 24.04
        |
CIS Ubuntu 24.04
        |
production-safe profile
        |
audit
        |
safe remediation
        |
verification
        |
rollback
```
The initial implementation should intentionally support a small number of
well-understood controls before expanding coverage.

Security automation should prioritize predictable behavior and evidence over
maximum benchmark coverage.

### Python Version

SecureBench targets:
```
Python >= 3.14,<4.0
```
### Ansible

Ansible is currently the execution backend.

The Python application owns:
```
policy
profiles
planning
transactions
rollback
verification orchestration
reporting
```
Ansible owns:
```
remote execution
privilege escalation
configuration management
idempotent system changes
```
This separation allows the execution layer to evolve independently from the
SecureBench policy engine.