# Dynamic Threat Modeling & Secure Function Coder
(Copied from C:\Users\leonf\.gemini\config\skills\secure-function-coder\SKILL.md)

This skill guides the agent to dynamically analyze function logic for security vulnerabilities from first principles—rather than simply matching a static list of keywords. It evaluates data trust boundaries, state transitions, and concurrency risks, calculates an empirical likelihood, and applies active defenses.

## 1. Dynamic Threat Modeling Framework
Whenever designing, writing, or refactoring a function, perform a dynamic contextual risk evaluation across these 4 vectors:
1. Trust Boundary & Input Surface
2. Execution & Side-Effect Vector
3. State, Timing & Concurrency
4. Logic & Desynchronization Attacks

## 2. In-Code Security Audit Specification
Document the dynamic threat assessment in the function's docstring/header:
```text
/**
 * [Function Summary]
 * 
 * SECURITY AUDIT:
 * - Dynamic Threat Vector: [Context-specific description of the potential attack or failure mode]
 * - CVE / CWE Mapping: [Dynamic mapping to closest patterns, e.g. CWE-XX / CVE pattern]
 * - Likelihood & Exploitability: [Low | Medium | High] (Score: X/10)
 *   * Threat Condition: [Under what exact circumstances can this occur?]
 * - Applied Mitigation: [Specific architectural/code-level hardening implemented below]
 */
```

## 3. Active Defense & Hardening Rules
1. Invariant Enforcement at the Gate: Validate preconditions, ranges, types, and schema immediately upon function entry. Fail early and explicitly.
2. Defensive Copies & Immutability: Prevent external mutation of internal collections or buffers (pass-by-value or freeze).
3. Constant-Time & Safe Operations: Use cryptographic timing-safe comparisons where secrets or tokens are touched.
4. Resource Constraints: Apply explicit timeouts, maximum iteration limits, and buffer boundaries to prevent unbounded CPU/memory consumption.
