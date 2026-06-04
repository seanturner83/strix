# Penetration Test — Rules of Engagement & Scope

## Authorization
I am the owner of these assets and authorize **comprehensive, aggressive security testing** against them.

This is a **pre-production environment**: there are no live users and the database contains only dummy
data. The goal is to find **every vulnerability now**, before the service carries real traffic.

**Aggressive testing is explicitly authorized**, including:
- Brute force and credential-stuffing attempts against auth endpoints.
- High-volume fuzzing and endpoint/parameter discovery.
- Rate-limit testing and load that may stress the service.
- Destructive actions (PATCH/DELETE, policy changes, data modification) — the data is disposable.

Be thorough. Prefer false positives investigated over missed vulnerabilities.

## Targets (in scope)
- **Backend source code:** https://github.com/tongaimaramba/sovereign-radar (the `vimba-radar-core` API)
- **Frontend app:** https://app.vimba.uk
- **API:** https://api.vimba.uk/api

Treat this as a **source-aware (white-box) assessment**: use the repository to understand the backend
logic, then validate findings dynamically against the live API and frontend. Map every dynamic finding
back to the responsible code (file + function).

## Infrastructure (for targeted testing)
- **Backend:** AWS **App Runner** (runs on ECS/Fargate). Probe for **SSRF reaching the cloud metadata
  service** — `http://169.254.169.254/...` and the ECS container-credentials endpoint
  `http://169.254.170.2/...` — to attempt theft of IAM/role credentials and environment secrets.
  Check for exposed AWS credentials in env vars, logs, or error output.
- **Database:** AWS **RDS PostgreSQL**. Tailor SQL injection to PostgreSQL (stacked queries, `::` casts,
  `pg_sleep()` time-based, error-based, `COPY`/`lo_*` for file/RCE vectors, info-schema enumeration).
- **Frontend:** **Cloudflare** in front of the app. Test for **origin exposure / WAF bypass** — try to
  reach the App Runner origin (`*.awsapprunner.com`) directly to bypass Cloudflare protections, and look
  for Cloudflare misconfigurations (real-IP leakage, cache poisoning, header trust issues).

## Priority findings to confirm and produce full PoCs for
1. **CRITICAL — Tenant isolation bypass via self-registration.**
   `POST /api/auth/signup` appears to assign new users to an existing tenant based solely on the
   free-text `company` field, with no invitation, email-domain verification, or approval — and grants
   `admin` role. This enables cross-tenant account takeover. Confirm end-to-end with two test companies,
   demonstrate cross-tenant access (read users/findings/sessions/policy, modify roles, invite users), and
   write a complete vulnerability report. In the source repo, locate the signup/tenant-assignment logic
   and cite the exact file/function.

2. **HIGH — Unauthenticated file upload.**
   `POST /api/airlock/scan` accepts uploads with no authentication. Test thoroughly for path traversal
   (filename), SSRF (incl. the AWS metadata endpoints above), XXE (note: XML sent as `csv`/`json`
   `log_type` was accepted with HTTP 200 in a prior run), and command injection / RCE in log processing.
   Trace the handler in the repo and confirm each lead with a working PoC.

## Additional areas of interest
- AuthN/AuthZ on all API endpoints (`/users`, `/users/invite`, `/users/{id}`, `/findings/current`,
  `/sessions/recent`, `/respond/policy`, `/respond/request`): IDOR, privilege escalation, missing
  server-side role checks.
- AWS Cognito JWT handling: token manipulation, `none` algorithm, expired-token acceptance,
  self-service modification of `custom:tenant_id`.
- Injection (PostgreSQL SQLi, NoSQL, command), SSTI, mass assignment / parameter pollution on signup & invite.
- Information disclosure: the OpenAPI spec is exposed (e.g. `/openapi.json`); stack traces; verbose errors; exposed secrets.
- Account enumeration via login / forgot-password / magic-link (timing or message differences).
- Business-logic flaws and missing rate limiting on auth endpoints (brute force is authorized).

## Cleanup
Data is disposable, so destructive testing is fine. Still, **list every account, tenant, and persistent
artifact you create** in the final report so I can clean them up.

## Deliverable
For every confirmed issue, produce a full vulnerability report (severity, CVSS, description, impact,
reproduction steps, PoC, affected endpoint/code location, and remediation guidance). Prioritize the two
items above, then work outward to comprehensive coverage. Map dynamic findings back to the responsible
code in the repository.
