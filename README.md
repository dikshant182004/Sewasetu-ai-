# Sewa Setu — Old Age Pension Portal

Department of Social Welfare, Government of Purvanchal. Maintained in-house.

## Running locally

Copy `.env.example` to `.env`, replace `ADMIN_PASSWORD` and `SECRET_KEY` with local-only secrets, then run:

```bash
docker compose up --build -d db app smsgw citizen-mcp officer-mcp
```

- Portal: http://localhost:8000
- Status portal: http://localhost:8000/status (mobile number + password; the password is the applicant's date of birth as DDMMYYYY)
- Departmental login: http://localhost:8000/admin (user `admin`, password from `ADMIN_PASSWORD`)
- Citizen MCP (Streamable HTTP): http://localhost:8100/mcp
- Citizen MCP health: http://localhost:8100/healthz
- Officer MCP (Streamable HTTP): http://localhost:8200/mcp
- Officer MCP health: http://localhost:8200/healthz
- SMS gateway console (simulated telecom): http://localhost:8000/__gateway/ — OTPs and notifications appear here once delivered. Do not expose this simulated inbox as a production SMS service.
- Database: Postgres, loaded from `seed/seed.sql` on first boot (~100k applications).

## Deploying on a server

Set PUBLIC_BASE_URL to the portal's public HTTPS address and set both MCP public URLs to their exact externally reachable resource URLs, including /mcp. The OAuth client must request the matching URL as resource; each MCP rejects tokens issued for another audience. Put the portal and both MCPs behind HTTPS.

Configure block-level officer access in OFFICER_BLOCK_ASSIGNMENTS, a JSON map from officer username to allowed block names. The default is the configured ADMIN_USERNAME assigned to Sonari only. For distinct OAuth officer accounts, set OFFICER_ACCOUNTS_JSON to a JSON map of username to password using deployment secrets; do not commit real credentials. The legacy web dashboard login remains global and must be restricted separately.

Example deployment values (use a secrets manager for passwords and keys):

    PUBLIC_BASE_URL=https://sewasetu.example.in
    CITIZEN_MCP_PUBLIC_URL=https://agents.example.in/citizen/mcp
    OFFICER_MCP_PUBLIC_URL=https://agents.example.in/officer/mcp
    OFFICER_BLOCK_ASSIGNMENTS={"admin":["Sonari"],"meera.das":["Rajapara"]}

After configuring your reverse proxy/TLS routes, start the services with:

    docker compose up --build -d db app smsgw citizen-mcp officer-mcp

## What the portal does

Citizen flow: mobile → OTP → personal details → address → bank details → age-proof upload → preview and declaration → application number. A nightly job (`scripts/deemed_approval.py`, via cron in the `scheduler` container) deems eligible pending applications approved after the 15-day statutory SLA.

Rules enforced at submission, in `validate_application()` in `app/app.py`: applicant is 60 years of age or above; required fields and an age-proof document are present; the scheme window is open; and the mobile number holds no other active (pending / approved / deemed-approved) application. A pending application can be withdrawn from the status portal, after which the same mobile may apply again.

Departmental users see a dashboard, list and filter applications, approve or reject pending ones, and see the audit trail per application.

## Layout

```
app/          Flask application, citizen and officer MCP services, templates, config, nightly job
seed/         seed.sql — production data snapshot
smsgw/        simulated SMS gateway
tests/        portal tests and citizen/officer MCP token-validation tests
docs/         hardening findings and MCP design notes
```

## OAuth and agent access

Sewa Setu is an OAuth authorization server. Third-party clients act for a citizen (scope `citizen`) or officer (scope `officer`) only after that person signs in on the portal and consents. Citizens sign in by mobile and OTP; officers use the departmental login. The application never handles the OTP or password.

- Discovery: `/.well-known/oauth-authorization-server` (RFC 8414)
- Registration: `/oauth/register` (RFC 7591), or a client ID metadata document URL as `client_id`
- Authorization: `/oauth/authorize` (authorization code with PKCE S256); the requested `resource` becomes the token audience (RFC 8707)
- Tokens: `/oauth/token`; RS256 JWT access tokens (20 minutes for citizens / 30 minutes for officers), refresh-token rotation and absolute session expiry
- Sign-out: `/oauth/revoke`; people can also end sign-ins in the portal's connected-applications page
- Public keys: `/.well-known/jwks.json`

The Citizen MCP is a separate service, defaults to the Sonari pilot block only (configurable with `CITIZEN_MCP_ALLOWED_BLOCKS`), and accepts only tokens whose issuer, exact audience, expiry, subject, role, and scope are valid for the citizen service. It exposes `get_scheme_rules`, `check_eligibility`, `save_application_draft`, `resume_application_draft`, `get_my_application`, and `submit_application`. It writes through the portal's shared validation and creation functions; it cannot approve cases.

The Officer MCP is a separate service on port 8200. It requires an officer-scoped token and a server-side block assignment, and exposes `list_my_pending_queue`, `get_case`, `get_case_evidence`, `record_case_decision`, and `get_recorded_decision`. Decisions go through the portal's existing `decide_application()` function and write to the portal audit log.

Design and testing notes: [docs/CITIZEN-MCP.md](docs/CITIZEN-MCP.md) and [docs/OFFICER-MCP.md](docs/OFFICER-MCP.md).

Long-lived officer program tokens can be issued at `/admin/tokens`; if used, their audience must be set to the exact Officer MCP public URL. Prefer the normal OAuth sign-in and consent flow for the assessment.

## Running the fixed portal and tests

```bash
cp .env.example .env
# Set ADMIN_PASSWORD and SECRET_KEY in .env, then:
docker compose up --build -d db app smsgw citizen-mcp officer-mcp
# Start the scheduler separately when ready to exercise deemed approval:
docker compose up -d scheduler
python -m unittest discover -s tests -v
```

Existing database (not a fresh `docker compose down -v`)? Apply the migration once:

```bash
docker compose exec -T db psql -U sewasetu sewasetu < app/migrations/001_integrity_and_otp_limits.sql
docker compose exec -T db psql -U sewasetu sewasetu < app/migrations/002_citizen_application_drafts.sql
```

Checks against the running database: `docker compose exec -T db psql -U sewasetu sewasetu < tests/verify_db.sql`.

Portal hardening findings: [docs/FINDINGS.md](docs/FINDINGS.md).
