# Account Server Documentation

Account Server provides a multi-tenant authentication and authorization system with OAuth 2.0 / OpenID Connect support.

## Quick Links

| Guide | Description |
|-------|-------------|
| [Integration Guide](integration-guide.md) | Complete API reference for user authentication, organizations, and applications |
| [Admin UI Integration](admin-ui-integration-guide.md) | Build admin interfaces with SSO authentication |

## Features

- **Multi-tenant Architecture** - Organizations, applications, and users in a hierarchical structure
- **OAuth 2.0 / OIDC** - Standards-compliant authentication with PKCE support
- **Admin SSO** - Single sign-on for administrative interfaces
- **User Management** - Create and manage end-users with JWT authentication
- **MFA Support** - TOTP-based multi-factor authentication
- **External OAuth** - Connect to Google, Slack, Microsoft, GitHub, and more

## Architecture

```
Administrator (sign up at auth.interactor.com)
    └── Organization (named container, e.g., "acme-corp")
            ├── Applications (OAuth clients for your services)
            │   └── Authenticate via client credentials
            └── Users (your end users)
                └── Authenticate via username/password or OAuth
```

## Getting Started

### 1. Register as an Administrator

```bash
curl -X POST https://auth.interactor.com/api/v1/admin/register \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Your Name",
    "email": "you@example.com",
    "password": "SecurePassword123!"
  }'
```

### 2. Create an Organization

After verifying your email and logging in:

```bash
curl -X POST https://auth.interactor.com/api/v1/admin/orgs \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "Content-Type: application/json" \
  -d '{"name": "my-org"}'
```

### 3. Create an Application

```bash
curl -X POST https://auth.interactor.com/api/v1/admin/orgs/my-org/applications \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "Content-Type: application/json" \
  -d '{"name": "my-backend"}'
```

### 4. Get an Access Token

```bash
curl -X POST https://auth.interactor.com/api/v1/oauth/token \
  -H "Content-Type: application/json" \
  -d '{
    "grant_type": "client_credentials",
    "client_id": "app_xxx",
    "client_secret": "sec_xxx"
  }'
```

For complete setup instructions, see the [Integration Guide](integration-guide.md).

## Common Use Cases

| Use Case | Documentation |
|----------|---------------|
| Backend service authentication (M2M) | [Integration Guide - Applications](integration-guide.md#application-management) |
| End-user authentication | [Integration Guide - OAuth/OIDC](integration-guide.md#oauth-20--oidc-user-authentication-recommended-for-user-facing-apps) |
| Building admin dashboards | [Admin UI Integration Guide](admin-ui-integration-guide.md) |
| Managing user accounts | [Integration Guide - User Management](integration-guide.md#user-management) |
| Implementing MFA | [Integration Guide - MFA](integration-guide.md#multi-factor-authentication-mfa) |

## API Base URL

**Production:** `https://auth.interactor.com/api/v1`

## Authentication Types

| Type | Format | Use Case |
|------|--------|----------|
| Admin JWT | `Authorization: Bearer admin_xxx` | Managing orgs, apps, users |
| App JWT | `Authorization: Bearer app_xxx` | Backend service operations |
| User JWT | `Authorization: Bearer user_xxx` | End-user operations |

## JWT Verification

Verify tokens using our JWKS endpoint:

```
https://auth.interactor.com/.well-known/jwks.json
```

## Support

For integration support, refer to the troubleshooting sections in each guide or contact your organization administrator.

---

## Claude AI Skills

The `.claude/skills/` directory contains skill files for AI-assisted integration:

| Skill | Description |
|-------|-------------|
| [interactor-auth](.claude/skills/i/interactor-auth/SKILL.md) | Backend authentication setup with OAuth client credentials |
| [interactor-credentials](.claude/skills/i/interactor-credentials/SKILL.md) | Managing credentials for external services (Google, Slack, etc.) |
