# Account Server Integration Guide

_Last verified: 2026-06-18_

This guide has been restructured into focused chapters. See the [integration-guide/](integration-guide/) directory:

1. [Overview](integration-guide/01-overview.md) — Architecture, token types, authentication methods
2. [Quick Start](integration-guide/02-quick-start.md) — Register, login, get tokens, make API calls
3. [Admin Profile](integration-guide/03-admin-profile.md) — Profile management, password, logout
4. [Organizations](integration-guide/04-organizations.md) — Org CRUD, members, invitations, permissions
5. [Applications](integration-guide/05-applications.md) — App CRUD, secret rotation, client credentials
6. [User Management](integration-guide/06-user-management.md) — Admin/app user CRUD, self-registration, user auth, identities
7. [OAuth / OIDC](integration-guide/07-oauth-oidc.md) — User authentication via OAuth 2.0, social login
8. [MFA](integration-guide/08-mfa.md) — TOTP setup, login flow, recovery codes
9. [Service API](integration-guide/09-service-api.md) — Token validation, access checks (service-to-service)
10. [Reference](integration-guide/10-reference.md) — Errors, rate limits, JWT verification, best practices
11. [Teams](integration-guide/11-teams.md) — Teams + memberships (subgrouping users within an Organization)

## Troubleshooting

Common authentication failures and how to resolve them:

- **401 Unauthorized** — Likely cause: an expired or malformed Bearer token (access tokens expire after 15 minutes; see [Reference](integration-guide/10-reference.md)). Fix: re-mint a token via the appropriate flow — refresh an admin/user session with its refresh token, or request a new app token through the client-credentials grant at `POST /oauth/token` — and send it as `Authorization: Bearer <token>`.
- **403 Forbidden** — Likely cause: an org/tenant scope mismatch, where the JWT `org` claim does not match the target resource's tenant/organization. Fix: mint or use a token whose `org` claim matches the target organization, and confirm the caller's membership and scope in that org.
- **Token rejected right after minting** — Likely cause: clock skew on the JWT `exp`/`nbf` claims, i.e. the client and server clocks are out of sync. Fix: sync system clocks via NTP, and allow a small verification leeway (a few seconds) when validating `exp`/`nbf`.
