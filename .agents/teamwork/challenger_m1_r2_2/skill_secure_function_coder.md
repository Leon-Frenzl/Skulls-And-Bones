# Dynamic Threat Modeling & Secure Function Coder
(Dumped from C:\Users\leonf\.gemini\config\skills\secure-function-coder\SKILL.md)

This skill guides the agent to dynamically analyze function logic for security vulnerabilities from first principles—rather than simply matching a static list of keywords. It evaluates data trust boundaries, state transitions, and concurrency risks, calculates an empirical likelihood, and applies active defenses.

## 1. Dynamic Threat Modeling Framework
1. Trust Boundary & Input Surface
2. Execution & Side-Effect Vector
3. State, Timing & Concurrency (Race conditions, TOCTOU, file locking)
4. Logic & Desynchronization Attacks

## 2. In-Code Security Audit Specification
- Dynamic Threat Vector
- CVE / CWE Mapping
- Likelihood & Exploitability
- Applied Mitigation

## 3. Active Defense & Hardening Rules
1. Invariant Enforcement at the Gate
2. Defensive Copies & Immutability
3. Constant-Time & Safe Operations
4. Resource Constraints
