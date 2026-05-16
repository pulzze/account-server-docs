# Account Server Documentation

Account Server provides a multi-tenant authentication and authorization system with OAuth 2.0 / OpenID Connect support.

## Integration Guide

| Chapter | Description |
|---------|-------------|
| [01 - Overview](integration-guide/01-overview.md) | Architecture, token types, authentication methods |
| [02 - Quick Start](integration-guide/02-quick-start.md) | Register, login, get tokens, make API calls |
| [03 - Admin Profile](integration-guide/03-admin-profile.md) | Profile management, password, logout |
| [04 - Organizations](integration-guide/04-organizations.md) | Org CRUD, members, invitations, permissions |
| [05 - Applications](integration-guide/05-applications.md) | App CRUD, secret rotation, client credentials |
| [06 - User Management](integration-guide/06-user-management.md) | Admin/app user CRUD, self-registration, user auth, identities |
| [07 - OAuth / OIDC](integration-guide/07-oauth-oidc.md) | User authentication via OAuth 2.0, social login |
| [08 - MFA](integration-guide/08-mfa.md) | TOTP setup, login flow, recovery codes |
| [09 - Service API](integration-guide/09-service-api.md) | Token validation, access checks (service-to-service) |
| [10 - Reference](integration-guide/10-reference.md) | Errors, rate limits, JWT verification, best practices |
| [11 - Teams](integration-guide/11-teams.md) | Teams + memberships (subgrouping users within an Organization) |

## Admin UI Guide

| Guide | Description |
|-------|-------------|
| [Admin UI Integration](admin-ui-integration-guide.md) | Build admin interfaces with SSO authentication |

## API Base URL

**Production:** `https://auth.interactor.com`
**API prefix:** `/api/v1`

## Claude AI Skills

The `.claude/skills/` directory contains skill files for AI-assisted integration:

| Skill | Description |
|-------|-------------|
| [interactor-auth](.claude/skills/i/interactor-auth/SKILL.md) | Backend authentication setup with OAuth client credentials |
| [interactor-credentials](.claude/skills/i/interactor-credentials/SKILL.md) | Managing credentials for external services |
