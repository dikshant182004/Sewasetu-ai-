# Sewa Setu — Old Age Pension Portal

Department of Social Welfare, Government of Purvanchal. Maintained in-house.

## Running

```
ADMIN_PASSWORD=pick-something docker compose up --build
```

- Portal: http://localhost:8000
- Status portal: http://localhost:8000/status (mobile number + password; the password is the applicant's date of birth as DDMMYYYY)
- Departmental login: http://localhost:8000/admin (user `admin`, password from `ADMIN_PASSWORD`)
- Citizen MCP (Streamable HTTP): http://localhost:8100/mcp
- Citizen MCP health: http://localhost:8100/healthz
- SMS gateway console (simulated telecom): http://localhost:8000/__gateway/ — OTPs and notifications appear here once delivered. Do not expose this simulated inbox as a production SMS service.
- Database: Postgres, loaded from `seed/seed.sql` on first boot (~100k applications).

## Deploying on a server

Set `PUBLIC_BASE_URL` to the portal's public HTTPS address. Set `CITIZEN_MCP_PUBLIC_URL` to the exact public MCP resource URL, including `/mcp`, for example `https://agents.example.in/citizen/mcp`. The OAuth client must request that exact URL as the `resource`; audience validation intentionally rejects tokens issued for another service. Put both services behind HTTPS.

```
PUBLIC_BASE_URL=https://sewasetu.example.in \
CITIZEN_MCP_PUBLIC_URL=https://agents.example.in/citizen/mcp \
ADMIN_PASSWORD=pick-something docker compose up --build -d
```

## What the portal does

Citizen flow: mobile → OTP → personal details → address → bank details → age-proof upload → preview and declaration → application number. A nightly job (`scripts/deemed_approval.py`, via cron in the `scheduler` container) deems eligible pending applications approved after the 15-day statutory SLA.

Rules enforced at submission, in `validate_application()` in `app/app.py`: applicant is 60 years of age or above; required fields and an age-proof document are present; the scheme window is open; and the mobile number holds no other active (pending / approved / deemed-approved) application. A pending application can be withdrawn from the status portal, after which the same mobile may apply again.

Departmental users see a dashboard, list and filter applications, approve or reject pending ones, and see the audit trail per application.

## Layout

```
app/          Flask application, citizen MCP service, templates, config, nightly job
seed/         seed.sql — production data snapshot
smsgw/        simulated SMS gateway
tests/        portal tests and citizen MCP token-validation tests
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

The Citizen MCP is a separate service, defaults to the Sonari pilot block only (configurable with `CITIZEN_MCP_ALLOWED_BLOCKS`), and accepts only tokens whose issuer, exact audience, expiry, subject, role, and scope are valid for the citizen service. It exposes `get_scheme_rules`, `check_eligibility`, `save_application_draft`, `resume_application_draft`, `get_my_application`, and `submit_application`. The last tool writes through the portal's shared validation and creation functions; it does not approve applications or expose officer tools.

**Citizen MCP design, security boundaries, run instructions and end-to-end test matrix:** see [docs/CITIZEN-MCP.md](docs/CITIZEN-MCP.md).

Long-lived officer program tokens are issued by an administrator at `/admin/tokens`; do not use them for citizen workflows.

## Running the fixed portal and tests

```bash
cp .env.example .env
# Set ADMIN_PASSWORD and SECRET_KEY in .env, then:
docker compose up --build -d db app smsgw citizen-mcp
# Start the scheduler separately when ready to exercise deemed approval:
docker compose up -d scheduler
python3 -m unittest discover -s tests -v
```

Existing database (not a fresh `docker compose down -v`)? Apply the migration once:

```bash
docker compose exec -T db psql -U sewasetu sewasetu < app/migrations/001_integrity_and_otp_limits.sql
docker compose exec -T db psql -U sewasetu sewasetu < app/migrations/002_citizen_application_drafts.sql
```

Checks against the running database: `docker compose exec -T db psql -U sewasetu sewasetu < tests/verify_db.sql`.

Portal hardening findings: [docs/FINDINGS.md](docs/FINDINGS.md).
