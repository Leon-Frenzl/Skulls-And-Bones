---
name: standards-compliance
description: >-
  Use this skill to identify, evaluate, and integrate relevant formal engineering standards (such as IEEE, ISO/IEC, IETF RFC, W3C, and POSIX) into code, data formats, and architecture whenever it provides concrete interoperability, precision, or reliability benefits.
---

# Formal Standards Compliance (IEEE / ISO / RFC)

This skill enables the agent to check for official, recognized technical standards governing a problem domain, evaluate whether compliance is beneficial, and incorporate the standard into the code and specifications.

---

## 1. Domain Standards Radar

Before implementing protocols, data models, math routines, or file formats, check the relevant standard bodies:

| Organization | Domain Examples | Key Standards to Reference |
| :--- | :--- | :--- |
| **IEEE** | Floating-point math, networking, verification & validation, software engineering | IEEE 754 (Float arithmetic), IEEE 829 (Test docs), IEEE 1003.1 (POSIX), IEEE 802 |
| **ISO / IEC** | Date/Time, character encoding, security, software lifecycle, quality models | ISO 8601 (Timestamps), ISO/IEC 27001 (Security), ISO/IEC 25010 (Software quality), ISO/IEC 10646 (Unicode) |
| **IETF (RFC)** | Internet protocols, HTTP, authentication, tokens, hashing, serialization | RFC 7519 (JWT), RFC 9110 (HTTP Semantics), RFC 8259 (JSON), RFC 4122 (UUID) |
| **W3C / WHATWG** | Web APIs, DOM, accessibility, URL parsing | W3C WCAG, WHATWG URL Standard, WebSockets |

---

## 2. Pragmatic Adoption Check

Do not blindly over-engineer. Formally evaluate:
* **Interoperability:** Does following the standard enable seamless communication with third-party tools or external systems?
* **Precision & Edge Cases:** Does the standard define edge cases (e.g., leap seconds, NaN handling, boundary rounding) that would otherwise cause subtle bugs?
* **Cost vs. Benefit:** Does full compliance add unreasonable overhead? If partial compliance is optimal, explicitly document the deviations.

---

## 3. Code Integration Protocol

When a standard is adopted:
1. **Cite the Standard in Header Comments:** Specify the standard body, standard number, and relevant section (e.g., `Conforms to IEEE 754-2019 Section 5.3` or `Implements RFC 9110 §8.3.1`).
2. **Use Standard Terminology:** Align variable, constant, and error names with standard definitions.
3. **Verify Compliance via Tests:** Include test assertions verifying boundary cases dictated by the specification.
