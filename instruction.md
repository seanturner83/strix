# Penetration Test — Rules of Engagement & Scope

## Authorization
I am the owner of these assets and authorize security testing against them.

## Targets (in scope)
- **Backend source code:** https://github.com/tongaimaramba/sovereign-radar (the `vimba-radar-core` API)
- **Frontend app:** https://app.vimba.uk
- **API:** https://api.vimba.uk/api

Treat this as a **source-aware (grey/white-box) assessment**: use the repository to understand
the backend logic, then validate findings dynamically against the live API and frontend.

## Out of scope / DO NOT
- Do **not** run high-volume fuzzing, brute force, or load that could degrade the production service (avoid DoS).
- Do **not** modify, delete, or exfiltrate data belonging to real users/tenants.
- Any account you create for testing must use clearly synthetic company names (e.g. `STRIXTEST-*`)
  and synthetic emails. **Clean up / report every test account and tenant you create** so I can remove them.
- If you must test destructive actions (PATCH/DELETE on users, policy changes), only do so against
  accounts/tenants **you created**, and revert changes afterward.

## Priority findings to confirm and produce full PoCs for
1. **CRITICAL — Tenant isolation bypass via self-registration.**
   `POST /api/auth/signup` appears to assign new users to an existing tenant based solely on the
   free-text `company` field, with no invitation, email-domain verification, or approval — and grants
   `admin` role. This enables cross-tenant account takeover. Confirm end-to-end with two synthetic
   companies, demonstrate cross-tenant access (read users/findings/sessions/policy, modify roles,
   invite users), and write a complete vulnerability report with reproduction steps and impact.
   In the source repo, locate the signup/tenant-assignment logic and cite the exact file/function.

2. **HIGH — Unauthenticated file upload.**
   `POST /api/airlock/scan` accepts uploads with no authentication. Test thoroughly for:
   path traversal (filename), SSRF, XXE (note: XML sent as `csv`/`json` `log_type` was accepted with
   HTTP 200 in a prior run), and command injection / RCE in log processing. Trace the handler in the
   repo and confirm each lead with a working PoC.

## Additional areas of interest
- AuthN/AuthZ on all API endpoints (`/users`, `/users/invite`, `/users/{id}`, `/findings/current`,
  `/sessions/recent`, `/respond/policy`, `/respond/request`): IDOR, privilege escalation, missing
  server-side role checks.
- AWS Cognito JWT handling: token manipulation, `none` algorithm, expired-token acceptance,
  self-service modification of `custom:tenant_id`.
- Injection (SQL/NoSQL/command), SSTI, mass assignment / parameter pollution on signup & invite.
- Information disclosure: the OpenAPI spec is exposed (e.g. `/openapi.json`); stack traces; verbose errors.
- Account enumeration via login / forgot-password / magic-link timing or message differences.
- Business-logic flaws and rate-limiting gaps on auth endpoints.

## Deliverable
For every confirmed issue, produce a full vulnerability report (severity, CVSS, description, impact,
reproduction steps, PoC, affected endpoint/code location, and remediation guidance). Prioritize the
two items above. Map dynamic findings back to the responsible code in the repository.
