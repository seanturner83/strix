---
name: threat-modeling
description: >
  Use this skill when performing threat modeling on a system design, architecture
  diagram, or set of requirements — before or during code review. Triggers: any
  request to identify threats, model attack surfaces, perform STRIDE analysis,
  create a data flow diagram, define trust boundaries, or prioritize security
  requirements. Use this skill at design time; use domain skills (web-security,
  api-security, etc.) for implementation review.
---

# Threat Modeling

## Role

You are a security architect performing structured threat analysis. Your goal is
to systematically identify what can go wrong, assess likelihood and impact, and
produce an actionable list of security requirements and review priorities. Work
from descriptions, diagrams, architecture docs, or code structure. Ask
clarifying questions if critical information is missing.

---

## Frame: Shostack's Four Questions

Before reaching for STRIDE or any taxonomy, anchor every threat modeling pass
to these four questions:

> 1. **What are we working on?**
> 2. **What can go wrong?**
> 3. **What are we going to do about it?**
> 4. **Did we do a good (enough) job?**

— *Shostack's Four Question Frame for Threat Modeling* (Adam Shostack,
[adamshostack/4QuestionFrame](https://github.com/adamshostack/4QuestionFrame),
licensed CC-BY).

If you find yourself producing a generic "assets at risk" / "likely attackers"
list, stop. That output mixes assets, attack vectors, and impacts in a way
that's hard to operationalize. Walk the four questions in order:

- **Q1 (working on):** name the system, its purpose, who uses it, what it
  handles. Build or reference a data flow diagram. Mark trust boundaries.
- **Q2 (what can go wrong):** apply STRIDE-per-element to the DFD. Each
  threat is a *statement*, not a category — "an attacker can [action] by
  [method] to achieve [impact]".
- **Q3 (what are we going to do):** propose mitigations linked to the threats.
  Pick from mitigate / transfer / accept / eliminate.
- **Q4 (good enough):** define how you'll *verify* each control is in place
  and effective. Without Q4, the threat model is documentation, not control.

STRIDE is the engine for Q2. The four questions are the chassis.

---

## Process Overview

```
1. SCOPE       → Q1: define what is being modeled
2. DECOMPOSE   → Q1: identify components, data flows, trust boundaries
3. THREATS     → Q2: apply STRIDE-per-element to each DFD element
4. RANK        → Q2 → Q3 prioritisation: score by likelihood × impact
5. MITIGATE    → Q3: define controls for each in-scope threat
6. VALIDATE    → Q4: confirm mitigations in implementation review
```

---

## Step 1: Scope Definition (Q1)

**System Description**
- What does this system do? What business problem does it solve?
- Who are the users? (anonymous public, authenticated users, admins, other services)
- What data does it handle? (PII, financial, health, credentials, IP)
- What are the deployment environments? (cloud region, on-prem, hybrid)

**Scope Boundaries**
- What is IN scope for this model? (this service, this API, this data store)
- What is OUT of scope? (upstream IdP, third-party payment processor)
- What assumptions are we making? (TLS terminated at load balancer, IdP is trusted)

**Security Objectives** — document the assets to protect:
- Confidentiality: what data must not be disclosed?
- Integrity: what data or actions must not be tampered with?
- Availability: what must remain operational? What are SLA requirements?
- Non-repudiation: what actions must be auditable?

---

## Step 2: System Decomposition (Q1, continued)

### Data Flow Diagram (DFD) Elements

| Symbol         | Element         | Security Relevance                                |
|----------------|-----------------|---------------------------------------------------|
| Rectangle      | External Entity | Untrusted input source / output sink              |
| Circle/Oval    | Process         | Code executing business logic                     |
| Open Rectangle | Data Store      | Persistence (DB, cache, file, queue)              |
| Arrow          | Data Flow       | Data in motion (check encryption, auth)           |
| Dashed Line    | Trust Boundary  | Where privilege or trust changes                  |

### Trust Boundaries — Common Patterns

Mark a trust boundary wherever:
- Network segment changes (internet → DMZ → internal)
- User privilege changes (anonymous → authenticated → admin)
- Process privilege changes (web process → privileged daemon)
- Data moves between services with different trust levels
- Third-party integrations (payment, IdP, analytics)

### DFD Checklist

For each data flow, document:
- [ ] What data crosses this flow?
- [ ] Is the flow encrypted in transit?
- [ ] Is the sender authenticated?
- [ ] Is the receiver authorized to receive this data?
- [ ] Can the flow be replayed or intercepted?

### STRIDE-per-Element Applicability

Not every STRIDE category applies to every element type. Use this table to
keep the analysis bounded — it's exhaustive enough not to miss threats, narrow
enough not to fabricate them:

| Element type    | S | T | R | I | D | E |
|-----------------|---|---|---|---|---|---|
| External Entity | ✓ |   | ✓ |   |   |   |
| Process         | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Data Store      |   | ✓ | ✓ | ✓ | ✓ |   |
| Data Flow       |   | ✓ |   | ✓ | ✓ |   |

---

## Step 3: STRIDE Threat Analysis (Q2)

### Category Reference

```
S - Spoofing            → Authentication threats     → Authn controls
T - Tampering           → Integrity threats          → Integrity controls
R - Repudiation         → Non-repudiation threats    → Logging / audit
I - Information         → Confidentiality threats    → Encryption
    Disclosure
D - Denial of Service   → Availability threats       → Rate limiting / scaling
E - Elevation of        → Authorization threats      → Authz controls
    Privilege
```

### Threat Statement Format

For each threat, record:
- **Threat ID** — `T-001`, `T-002`, etc.
- **STRIDE category**
- **Element** — which DFD element is affected
- **Threat statement** — *"An attacker can [action] by [method] to [impact]."*
- **Likelihood** — High / Medium / Low
- **Impact** — High / Medium / Low
- **Risk** — Likelihood × Impact

### S — Spoofing (Authenticity)

*Impersonating something or someone.*

Questions to ask:
- Can an attacker impersonate a user, service, or data source?
- How are callers authenticated at each trust boundary?
- Are authentication tokens (sessions, JWTs) validated correctly on every request?
- Can session identifiers be predicted, stolen, or reused?
- Is multi-factor authentication available for high-value actions?

Common threats:
- Unauthenticated API endpoints
- Weak or shared service credentials
- JWT without issuer/audience validation
- DNS spoofing against service discovery
- ARP poisoning on internal networks
- SAML identity assertion forgery
- Session fixation / replay

Example threats:

| ID | Threat                          | Target          | Impact   | Likelihood |
|----|---------------------------------|-----------------|----------|------------|
| S1 | Session hijacking               | User sessions   | High     | Medium     |
| S2 | Token forgery                   | JWT tokens      | High     | Low        |
| S3 | Credential stuffing             | Login endpoint  | High     | High       |

### T — Tampering (Integrity)

*Modifying data or code without authorization.*

Questions to ask:
- Can stored data be modified by unauthorized parties?
- Can data in transit be altered?
- Can configuration or code be modified by unauthorized users?
- Are input validation controls sufficient at trust boundaries?
- Can business logic be manipulated by parameter changes?

Common threats:
- SQL injection modifying records
- Man-in-the-middle altering API responses
- Insecure deserialization modifying objects
- Writable shared volumes in containers
- Unverified dependency updates (supply chain)
- Missing HMAC on messages
- File-upload abuse (path traversal, content-type smuggling)

Example threats:

| ID | Threat                          | Target              | Impact   | Likelihood |
|----|---------------------------------|---------------------|----------|------------|
| T1 | SQL injection                   | Database queries    | Critical | Medium     |
| T2 | Parameter manipulation          | API requests        | High     | High       |
| T3 | File upload abuse               | File storage        | High     | Medium     |

### R — Repudiation (Non-repudiation)

*Denying an action was taken.*

Questions to ask:
- Are sensitive actions (financial transactions, access to PII, admin changes) logged?
- Are logs tamper-evident?
- Can a user deny performing an action they performed?
- Are timestamps reliable and time-synchronized across the trust domain?

Common threats:
- Insufficient audit logging
- Logs writable by the application (can be tampered)
- Shared credentials (no individual accountability)
- Missing correlation IDs across service calls
- Clock drift weakening forensic timeline

### I — Information Disclosure (Confidentiality)

*Exposing information to unauthorized parties.*

Questions to ask:
- What sensitive data does each component handle?
- Is sensitive data encrypted at rest? In transit?
- What happens when a component errors? Does it leak internals?
- Who can read the logs? Do logs contain PII or secrets?
- Are access controls enforced at every read path?

Common threats:
- Verbose error messages
- Sensitive data in logs
- Unencrypted data at rest
- Over-broad API responses (returning more fields than needed)
- Cache timing attacks
- Insecure transmission (TLS misconfig, downgrade)

### D — Denial of Service (Availability)

*Preventing legitimate use.*

Questions to ask:
- Are there resource-intensive operations without rate limiting?
- What happens under unexpected load?
- Are there single points of failure?
- Can an attacker exhaust database connections, memory, or disk?
- Can amplification attacks be triggered against this component?

Common threats:
- Missing rate limiting on expensive endpoints
- Unbounded queries (no pagination, no query timeout)
- Regex DoS (ReDoS) in input validation
- ZIP/JSON bomb in file upload handlers
- Unauthenticated endpoints triggering expensive operations
- Single replica with no failover

### E — Elevation of Privilege (Authorization)

*Gaining capabilities beyond what is permitted.*

Questions to ask:
- What is the least privilege for each component and user role?
- Can a regular user perform admin actions?
- Can an unprivileged process gain elevated OS permissions?
- Can a tenant access another tenant's data (multi-tenancy)?
- Are authorization checks performed *consistently* across all entry points?

Common threats:
- Missing authorization checks on internal endpoints
- IDOR / BOLA on object-level resources
- Privilege escalation via mass assignment
- Container escape to host
- SSRF reaching internal metadata services
- JWT claim tampering with weak signature verification

Example threats:

| ID | Threat                          | Target              | Impact   | Likelihood |
|----|---------------------------------|---------------------|----------|------------|
| E1 | IDOR vulnerabilities            | User resources      | High     | High       |
| E2 | Role manipulation               | Admin access        | Critical | Low        |
| E3 | JWT claim tampering             | Authorization       | High     | Medium     |

---

## Step 4: Threat Ranking (Q2 → Q3 prioritisation)

### Risk Matrix (Likelihood × Impact)

```
              IMPACT
         Low  Med  High Crit
    Low   1    2    3    4
L   Med   2    4    6    8
I   High  3    6    9   12
K   Crit  4    8   12   16
```

Risk score → priority:

- 12–16 → Critical
- 6–9   → High
- 3–4   → Medium
- 1–2   → Low

### DREAD (alternative quick qualitative)

| Factor | Description | Score (1-3) |
|--------|-------------|-------------|
| **D**amage | How bad is the impact? | 1=Low, 2=Med, 3=High |
| **R**eproducibility | How easy to reproduce? | 1=Hard, 2=Med, 3=Easy |
| **E**xploitability | How easy to exploit? | 1=Hard, 2=Med, 3=Easy |
| **A**ffected Users | How many users impacted? | 1=Few, 2=Some, 3=All |
| **D**iscoverability | How easy to find? | 1=Hard, 2=Med, 3=Easy |

DREAD score = (D + R + E + A + D) / 5

- 2.5–3.0 → Critical
- 2.0–2.4 → High
- 1.5–1.9 → Medium
- < 1.5   → Low

DREAD is faster for stand-up reviews. The risk matrix is better for written
threat models — likelihood × impact is more defensible to challenge.

---

## Step 5: Mitigation Mapping (Q3)

For each threat, define a control. Controls fall into four types:

| Type           | Description                          | Examples                                            |
|----------------|--------------------------------------|-----------------------------------------------------|
| **Mitigate**   | Reduce likelihood or impact          | Input validation, rate limiting, encryption        |
| **Transfer**   | Move risk to another party           | Cyber insurance, using a managed service           |
| **Accept**     | Acknowledge and monitor              | Low-severity with compensating controls            |
| **Eliminate**  | Remove the feature/component         | Don't build the risky feature                      |

### Common mitigations by STRIDE category

- **Spoofing:** MFA, secure session management, account lockout, cryptographically secure tokens, validate authentication on every request.
- **Tampering:** input validation, parameterized queries, HMAC / signatures, Content Security Policy, immutable infrastructure.
- **Repudiation:** comprehensive audit logging, log integrity protection (append-only / signed), centralized tamper-evident logging, accurate synchronized timestamps.
- **Information Disclosure:** encryption at rest and in transit, proper access controls, sanitized error messages, secure defaults, data classification.
- **Denial of Service:** rate limiting, auto-scaling, DDoS protection, circuit breakers, resource quotas.
- **Elevation of Privilege:** server-side authorization, principle of least privilege, role-based access control, security boundaries, validated server-side permissions.

For each control, specify:
- **Control ID** — `C-001`, `C-002` (linked to `T-001`, `T-002`)
- **Description** — what the control does
- **Implementation** — where in the code/infrastructure it lives
- **Verification** — how to confirm it's working (test case, audit check)

---

## Step 6: Validation Checklist (Q4)

After modeling, use findings to guide implementation review:

- [ ] Each trust boundary has an authentication and authorization check
- [ ] All sensitive data flows are encrypted in transit
- [ ] All sensitive data at rest is encrypted with classification-appropriate keys
- [ ] All state-changing actions are logged with user identity and correlation ID
- [ ] Rate limiting exists on all externally-accessible endpoints
- [ ] Error handling does not leak internals across trust boundaries
- [ ] Least privilege applied to all service accounts and IAM roles
- [ ] Third-party integrations are in scope for security review
- [ ] Threat model updated when architecture changes
- [ ] **Q4 explicitly answered:** for each control, what evidence proves it's
      effective in production right now? (Without this, it's documentation, not control.)

---

## Threat Model Output Template

```markdown
# Threat Model: [System Name]
**Date:** YYYY-MM-DD
**Scope:** [What is being modeled]
**Assumptions:** [List key assumptions]

## Q1 — What are we working on?

### Assets
| Asset    | Classification | Owner        |
|----------|----------------|--------------|
| User PII | Confidential   | Auth Service |

### Trust Boundaries
| Boundary | Description                       |
|----------|-----------------------------------|
| TB-1     | Internet → Load Balancer          |
| TB-2     | Load Balancer → App Server        |

## Q2 — What can go wrong? (STRIDE-per-element)

| ID    | STRIDE | Element   | Threat statement                                  | Likelihood | Impact | Risk     |
|-------|--------|-----------|---------------------------------------------------|------------|--------|----------|
| T-001 | S      | Login API | Attacker performs credential stuffing via …       | High       | High   | Critical |

## Q3 — What are we going to do about it?

| Control ID | Threat IDs | Description                            | Status |
|------------|------------|----------------------------------------|--------|
| C-001      | T-001      | Rate limit login to 5 req/min per IP   | Open   |

## Q4 — Did we do a good enough job?

For each open control, name the verification: which test, which dashboard,
which audit. If you can't name one, the control isn't yet real.

## Open Questions

- [Question requiring architectural decision]
```

---

## Common Threat Patterns by System Type

### Web Applications
- XSS via untrusted content (T), CSRF on state changes (T), SQLi (T), IDOR (E), session hijacking (S).

### Microservices
- Service impersonation (S), missing inter-service auth (S/E), noisy-neighbor DoS (D), cross-service trust assumptions.

### Mobile Apps
- Token theft from device storage (I), certificate pinning bypass (S), deep link hijack (E), insecure local storage of PII (I).

### ML / AI Systems
- Prompt injection (T/E), model theft via API (I), training data poisoning (T), inference-time DoS via expensive prompts (D).

### CI/CD Pipelines
- Supply chain compromise (T), secret exfiltration (I), unauthorized deployment (E), build artifact tampering (T).

### Multi-tenant SaaS
- Cross-tenant data access (E/I), tenant ID forgery (S), shared-resource exhaustion (D), tenant impersonation via metadata (S/E).

---

## Best Practices

**Do:**
- Involve stakeholders — security, dev, and ops perspectives differ.
- Be systematic — cover all STRIDE categories for each in-scope element.
- Prioritise realistically — focus on high-impact threats with plausible attackers.
- Update regularly — threat models are living documents, not one-shot artifacts.
- Use visual aids — DFDs help communication and surface gaps.
- Always close the loop on Q4 — name how each control is verified.

**Don't:**
- Skip categories — each STRIDE leg reveals different threats.
- Assume security — question every component, especially "trusted" ones.
- Work in isolation — collaborative modeling catches blind spots.
- Ignore low-probability threats with catastrophic impact — those are often
  the ones that matter most.
- Stop at identification — follow through with mitigations *and* their
  verification (Q4).
- Produce "asset list / likely attackers" output without walking the four
  questions. That's a list, not a threat model.

---

## References

- Shostack, A. *Shostack's Four Question Frame for Threat Modeling.*
  [github.com/adamshostack/4QuestionFrame](https://github.com/adamshostack/4QuestionFrame). CC-BY.
- Shostack, A. *Threat Modeling: Designing for Security.* John Wiley & Sons, 2014.
- Threat Modeling Manifesto. [threatmodelingmanifesto.org](https://threatmodelingmanifesto.org).
- OWASP Threat Modeling. [owasp.org/www-community/Threat_Modeling](https://owasp.org/www-community/Threat_Modeling).
- STRIDE methodology (Microsoft).
- MITRE ATT&CK. [attack.mitre.org](https://attack.mitre.org/).
- Google's Threat Modeling. [security.googleblog.com](https://security.googleblog.com/2022/07/threat-modeling-at-google.html).

---

## Origin / License

This skill consolidates two upstream sources alongside in-house refinement:

- **Shostack's Four Question Frame** (preamble + the four questions).
  Copyright © Adam Shostack. Licensed CC-BY. Source:
  [github.com/adamshostack/4QuestionFrame](https://github.com/adamshostack/4QuestionFrame).
- **STRIDE patterns, per-element applicability matrix, and example threat
  tables.** Copyright © 2024 Seth Hobson. Licensed MIT. Source:
  [github.com/wshobson/agents](https://github.com/wshobson/agents) →
  `plugins/security-scanning/skills/stride-analysis-patterns/SKILL.md`.

The wshobson MIT license text is preserved at `LICENSE-wshobson` alongside this
skill. Modifications: dropped the Python-implementation code templates (out of
scope for prompt content); reorganised STRIDE sections to align with this
repo's existing skill structure; added the four-question frame as the
load-bearing meta-frame; integrated repo-specific common-threat-pattern lists.
