# Critical Thinking & Decision Framework

This skill guides the agent to perform an objective, unvarnished critical evaluation of ideas, proposals, architectures, and algorithms. It strips away hype, conducts a structured pro/con analysis, scores decision dimensions (1-10), and commits to a clear, justified decision.

## Evaluation Workflow

When faced with an idea, architectural dilemma, or competing approaches:

### 1. Objective Deconstruction
* Formulate the core hypothesis or proposal in 1-2 precise sentences.
* Clarify the problem it actually solves vs. perceived benefits.
* Identify hidden assumptions and unstated prerequisites.

### 2. Pro & Contra Analysis
Present arguments with depth and honesty:

* **Arguments FOR (Pros):**
  * Concrete measurable advantages (e.g. latency, developer ergonomics, scalability).
  * Direct alignment with technical goals.
* **Arguments AGAINST (Cons & Devil's Advocate):**
  * Technical debt, operational complexity, cognitive load on the team.
  * Failure modes, migration friction, vendor lock-in, and maintenance overhead.
  * What breaks if the system scales 10x or if dependencies deprecate?

### 3. Quantitative Decision Matrix (Scoring 1-10)

Score each dimension from **1 (Very Poor / High Risk)** to **10 (Excellent / Minimal Risk)**:

| Criterion | Score (1-10) | Evaluation & Justification |
| :--- | :---: | :--- |
| **Feasibility & Effort** | ?/10 | Ease of implementation and dependency footprint |
| **Performance & Scalability** | ?/10 | Throughput, latency, memory, resource efficiency |
| **Maintainability & Elegance** | ?/10 | Code readability, testability, low cognitive overhead |
| **Robustness & Security** | ?/10 | Failure recovery, fault tolerance, attack surface |
| **Future-Proofing / Flexibility** | ?/10 | Adaptability to changing requirements without rewrites |
| **Total / Weighted Score** | **?/50** | **Overall quantitative rating** |

### 4. Definitive Decision & Action Plan

* **The Decision:** State a clear, unambiguous verdict (**Adopt**, **Reject**, or **Pivot to Alternative**). Do NOT leave the user with an ambivalent "it depends".
* **Justification:** Synthesize why the highest-weighted trade-offs dictate this choice.
* **Concrete Next Steps:** List the immediate technical actions to execute the decision.
