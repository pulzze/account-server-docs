# Overview

Account Server provides a **four-tier hierarchical authentication system** for multi-tenant platforms.

## Architecture

```
Administrator (sign up at auth.interactor.com)
    └── Organization (named container, e.g., "acme-corp")
            ├── Applications (OAuth clients for your services)
            │   └── Authenticate via client credentials → App JWT
            └── Users (your end users)
                └── Authenticate via username/password or OAuth → User JWT
```

## Key Concepts

- **Administrators** sign up, manage organizations, and configure applications
- **Organizations** are named containers (globally unique slugs, like GitHub usernames)
- **Applications** are M2M OAuth clients for your backend services
- **Users** are end-users of your application, scoped to an organization

## Token Types

| Type | Issued To | Contains | Lifetime |
|------|-----------|----------|----------|
| Admin JWT | Administrators | `sub` (admin ID), `type: "admin"`, `email` | 15 min |
| App JWT | Applications | `sub` (client ID), `type: "app"`, `org` | 15 min |
| User JWT | End users | `sub` (user ID), `type: "user"`, `org`, `username` | 15 min |

All tokens are signed RS256 JWTs. Verify them using the [JWKS endpoint](10-reference.md#jwt-verification).

## Base URL

```
Production: https://auth.interactor.com
API prefix: /api/v1
```

## Choosing an Authentication Method

```
Is this for end-user authentication?
│
├─ YES → Is this a web app, SPA, or mobile app?
│        │
│        ├─ YES → Use OAuth/OIDC (see 07-oauth-oidc.md)
│        │        • User credentials never touch your servers
│        │        • Supports social login (Google, GitHub)
│        │
│        └─ NO → Trusted first-party backend?
│                 │
│                 ├─ YES → Direct API login (see 06-user-management.md)
│                 │
│                 └─ NO → Use OAuth/OIDC
│
└─ NO → Backend-to-backend (M2M)?
         │
         └─ YES → OAuth 2.0 Client Credentials (see 05-applications.md)
```

## ID Formats

All public IDs use prefixes for easy identification:

| Entity | Prefix | Example |
|--------|--------|---------|
| Administrator | `adm_` | `adm_Ro5o8o9t-M` |
| Application | `app_` | `app_isfZqMSUgiqf_KKzC3W6` |
| User | `usr_` | `usr_VuUVJd8cE6` |
| Client Secret | `sec_` | `sec_Lajg4iOkZBjmwaAwlaSXTSyULZ9mewcrVE88qNIne09T` |
