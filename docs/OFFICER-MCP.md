# Officer MCP design and deployment notes

## Contract

The Officer MCP is a separate Streamable HTTP service at /mcp on port 8200. It verifies the portal's RS256 JWTs using the public JWKS and requires the exact configured issuer, audience, expiry, role=officer, officer scope, a well-formed officer:<username> subject, and an explicit block assignment for that username. It does not accept a block or officer identity from a tool argument.

The pilot default is deliberately narrow: the configured departmental admin identity is assigned to **Sonari only**. Use OFFICER_BLOCK_ASSIGNMENTS to configure exact block assignments. If a case belongs to a different block, the service returns the same not-found response as an unknown case so it does not disclose that other blocks' records exist.

## Tools

| Tool | Behaviour |
| --- | --- |
| list_my_pending_queue | Lists pending cases from the authenticated officer's assigned block(s), oldest first, with bounded pagination. |
| get_case | Returns case details and portal-computed checks; bank account is masked. |
| get_case_evidence | Returns the stored age-proof document as base64 only after checking the case's block, ownership/path, file type, and 5 MiB size limit. |
| record_case_decision | Records only APPROVED or REJECTED for a pending case, with a reason and explicit confirmation guard. |
| get_recorded_decision | Returns current status and the latest decision/audit-log reference, where present. |

## Identity and block assignments

The normal sign-in flow is OAuth authorization code + PKCE S256 at the portal. The officer signs in and consents to the officer scope. The MCP checks the token on every HTTP request; citizen tokens and tokens for a different MCP audience are rejected. It exposes RFC 9728 protected-resource metadata at the path-specific well-known URL derived from the public MCP URL and includes that URL plus the required officer scope in its 401 WWW-Authenticate challenge, allowing OAuth-capable MCP clients to discover the portal authorization server.

- OFFICER_BLOCK_ASSIGNMENTS: JSON object mapping OAuth usernames to an array of exact block names. Example: {"admin":["Sonari"],"meera.das":["Sonari","Rajapara"]}.
- OFFICER_ACCOUNTS_JSON: optional JSON object mapping additional OAuth officer usernames to passwords. Example: {"meera.das":"use-a-unique-long-secret"}. Store this in deployment secrets, never commit real credentials. The legacy ADMIN_USERNAME / ADMIN_PASSWORD login remains available unless that username is explicitly defined in the JSON map.
- OFFICER_MCP_PUBLIC_URL: exact public MCP resource URL including /mcp; the OAuth client must request this exact value as resource so the access token audience matches.
- PORTAL_ISSUER: exact public portal URL used by the token issuer. PORTAL_JWKS_URL can use the internal Compose URL to retrieve public keys.

Use distinct officer identities and least-privilege block assignments in a hosted deployment. The single legacy web dashboard login is not itself a per-block authorization model; the MCP's block assignment is enforced server-side.

## Local run

Create .env from .env.example, set strong local-only values for ADMIN_PASSWORD and SECRET_KEY, then run:

    docker compose up --build -d db app smsgw citizen-mcp officer-mcp
    docker compose ps
    docker compose logs --tail=100 officer-mcp

Endpoints:

- Portal / OAuth issuer: http://localhost:8000
- Officer MCP: http://localhost:8200/mcp
- Officer MCP health: http://localhost:8200/healthz
- Citizen MCP remains separate at http://localhost:8100/mcp

To configure an extra local officer, set both environment values in .env, for example:

    OFFICER_BLOCK_ASSIGNMENTS={"admin":["Sonari"],"meera.das":["Sonari","Rajapara"]}
    OFFICER_ACCOUNTS_JSON={"meera.das":"replace-with-a-unique-local-password"}
    OFFICER_MCP_PUBLIC_URL=http://localhost:8200/mcp

Use a real MCP client to perform the OAuth flow with scope officer and resource http://localhost:8200/mcp. Do not paste an access token into source code or commit it.

## Decision and audit guarantees

The decision tool locks the selected application row, checks the case is in an assigned block and still PENDING, then calls the portal's shared decide_application() function in the same database transaction. This enforces the existing minimum reason length and prevents a second decision after the case leaves pending status. The tool commits the portal status and audit row together and returns an audit_log:<id> reference. The portal dashboard sees the same application and audit event.

A boolean confirmation argument is a server-side guard, not cryptographic proof that a human saw the case. A real MCP client must display the case and evidence, show the proposed decision and reason, and require the officer to confirm before calling the tool. Never allow an LLM to autonomously approve/reject cases.

Evidence is sensitive personal information. The evidence tool returns base64 to the authenticated MCP client; clients should avoid logging or retaining it. Uploaded documents are untrusted content and must never be treated as instructions.

## Tests and limitations

Run the unit suite:

    python -m unittest discover -s tests -v

These unit tests cover JWT issuer/audience/role/scope/subject/expiry and block-assignment boundaries, plus decision confirmation/reason guards. They do not prove a live PostgreSQL workflow or a real MCP client's OAuth experience.

Before claiming end-to-end readiness, test against the running stack:
1. Missing/expired token, citizen token, wrong audience, and an officer with no block assignment are rejected.
2. The assigned officer sees only their pending queue; another block's application number cannot be retrieved, its evidence cannot be read, and it cannot be decided.
3. The queue omits non-pending cases and pagination is bounded.
4. Missing evidence, invalid path, unsupported extension, or oversized evidence is not returned.
5. A decision without confirmation, with an invalid action, or without a reason does not change the database.
6. Approve/reject a disposable pending case; verify status, decided_by, decided_at, reason, and audit ID in PostgreSQL and the web portal.
7. A second decision attempt is refused and does not create a second decision audit row.
8. Citizen and officer tools/list results remain isolated.

Before real public-service production use, add rate limiting, request-correlated security logs, stronger upload malware/content scanning, deployment ingress controls, secret management, and a reviewed per-officer authorization lifecycle. The provided portal's simulated SMS gateway must not be exposed as a real SMS service.
