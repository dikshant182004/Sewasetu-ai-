# Citizen MCP design and deployment notes

## Contract

The citizen service is a separate Streamable HTTP MCP endpoint at `/mcp` on port 8100. The pilot allowlist defaults to **Sonari only** (the block named in the Director's example); configure `CITIZEN_MCP_ALLOWED_BLOCKS` with an explicit comma-separated subset of portal-supported blocks only after evaluation. It is deliberately not mounted into the officer tool surface. It authenticates each HTTP request using the portal's RS256 JWKS and checks issuer, exact audience, expiry, citizen role, citizen scope, and the `citizen:<mobile>` subject. It also advertises RFC 9728 protected-resource metadata and includes a resource_metadata/scope challenge in 401 responses so OAuth-capable MCP clients can discover the portal authorization server. Tool arguments cannot select another applicant's mobile number.

Drafts live in a separate `application_drafts` table and are not applications; they never enter the officer queue. The authenticated subject determines the draft key. The portal remains the system of record for submitted applications. `submit_application` calls `portal.validate_application()`, `portal.store_age_proof()`, and `portal.create_application()`; it does not duplicate the eligibility rules or write a parallel application table. A database uniqueness constraint remains the final defense against concurrent active submissions. The server returns an application number only after the database commit succeeds.

## Tools

| Tool | Purpose | Annotation |
| --- | --- | --- |
| `get_scheme_rules` | Live scheme configuration, required fields, blocks, SLA | Read-only, idempotent |
| `check_eligibility` | Preflight details with the portal's validator; no write | Read-only, idempotent |
| `save_application_draft` | Save or update the authenticated citizen's partial form data | Mutating, idempotent |
| `resume_application_draft` | Retrieve that citizen's saved draft and missing fields | Read-only, idempotent |
| `get_my_application` | Latest application for the verified token subject | Read-only, idempotent |
| `submit_application` | Validate and submit a complete application with age proof | Mutating, destructive hint, non-idempotent |

The client should show a human confirmation before invoking `submit_application`. The boolean confirmation argument is a workflow guard, not a substitute for a trusted client-side confirmation UI. Tool annotations are advisory metadata; authorization and validation are enforced server-side.

## Local run

Set `ADMIN_PASSWORD`, `SECRET_KEY`, and `PUBLIC_BASE_URL` in `.env`. For local testing:

```bash
docker compose up --build -d db app smsgw citizen-mcp
```

- Portal: `http://localhost:8000`
- Citizen MCP: `http://localhost:8100/mcp`
- Health: `http://localhost:8100/healthz`

Configure `CITIZEN_MCP_PUBLIC_URL` to the exact public resource URL (including `/mcp`) when deployed. The OAuth client must request that exact value as the `resource` during authorization; the access token's `aud` must match it. Keep the portal and MCP behind HTTPS in production. The separate Officer MCP uses port 8200, a distinct audience, officer role/scope checks, per-officer block assignments, and its own tool registry; see [docs/OFFICER-MCP.md](OFFICER-MCP.md).

## Security boundaries and known limitations

- JWTs are verified with the portal's public JWKS; the MCP process does not need the portal's private signing key. In Compose, the JWKS is fetched over the internal `app:8000` service address while issuer and audience claims are still validated against their exact public URLs.
- Only the verified token subject determines which mobile number is queried or used for submission.
- SQL values are parameterized, uploaded file names are passed to the portal's server-side file validator, and application status is read from the database.
- The MCP does not make officer decisions, alter statuses, issue tokens, or expose the officer tool set.
- A boolean tool argument cannot independently prove that a human saw and confirmed a summary. Enforce confirmation in the MCP client UX as well as server-side workflow.
- This assessment implementation shares the portal's upload volume and database and is intended for the supplied exercise. Before real public-service production use, add per-subject/IP rate limiting, structured security audit events with request IDs, a durable expiring submission-challenge store, malware/content scanning for uploads, tighter network ingress controls, and integration tests against a disposable PostgreSQL instance.
- The supplied portal has other pre-existing deployment risks documented in `docs/FINDINGS.md`, including the simulated SMS inbox. Do not expose that simulation as a real production SMS service.

## Test expectations

Run the existing portal suite with:

```bash
python -m unittest discover -s tests -v
```

Also test the deployed MCP with a real Streamable HTTP MCP client and the portal database. Required cases include: missing/expired token; wrong issuer/audience; officer token on citizen endpoint; token for citizen A attempting to access citizen B; valid citizen reads; under-age applicant; closed scheme window; unsupported block; malformed IFSC/account; invalid or oversized age proof; active duplicate; concurrent duplicate submissions; confirmed successful submission visible in the portal; retry after uncertain response; and no officer-only tools in citizen `tools/list`. Do not mark these end-to-end cases as passed until run against the deployed stack.
