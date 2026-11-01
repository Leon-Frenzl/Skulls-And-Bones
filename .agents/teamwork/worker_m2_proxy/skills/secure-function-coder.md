---
name: secure-function-coder
description: >-
  Use this skill whenever writing, refactoring, or reviewing functions and methods to perform dynamic first-principles threat modeling, identify vulnerability vectors (including CVE/CWE patterns), calculate risk likelihood, and implement targeted code hardening.
---

# Dynamic Threat Modeling & Secure Function Coder

This skill guides the agent to dynamically analyze function logic for security vulnerabilities from first principles—rather than simply matching a static list of keywords. It evaluates data trust boundaries, state transitions, and concurrency risks, calculates an empirical likelihood, and applies active defenses.

---

## 1. Dynamic Threat Modeling Framework

Whenever designing, writing, or refactoring a function, perform a dynamic contextual risk evaluation across these 4 vectors:

1. **Trust Boundary & Input Surface:**
   - Where do inputs originate? (External untrusted user input, environment variables, network sockets, IPC, database)?
   - Can inputs mutate state, trigger unexpected branching, or violate semantic invariants?
2. **Execution & Side-Effect Vector:**
   - Does this function interact with system resources, memory buffers, sub-processes, file descriptors, or external network endpoints?
   - What happens under abnormal terminations, timeouts, network partitions, or resource exhaustion?
3. **State, Timing & Concurrency:**
   - Is there shared mutable state? Check for Race Conditions, Time-of-Check to Time-of-Use (TOCTOU), and asynchronous reentrancy.
   - Are timing side-channels possible (e.g., non-constant time comparison of secrets)?
4. **Logic & Desynchronization Attacks:**
   - Look beyond standard injection: evaluate state desynchronization, integer wraps/overflows, precision loss, prototype pollution, and serialization anomalies.

---

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

---

## 3. Active Defense & Hardening Rules

1. **Invariant Enforcement at the Gate:** Validate preconditions, ranges, types, and schema immediately upon function entry. Fail early and explicitly.
2. **Defensive Copies & Immutability:** Prevent external mutation of internal collections or buffers (pass-by-value or freeze).
3. **Constant-Time & Safe Operations:** Use cryptographic timing-safe comparisons where secrets or tokens are touched.
4. **Resource Constraints:** Apply explicit timeouts, maximum iteration limits, and buffer boundaries to prevent unbounded CPU/memory consumption.
