# Quick Start

Minimal steps to go from zero to making authenticated API calls.

## 1. Register as an Administrator

Registration creates your admin account, first organization, and a default application — all in one step.

```bash
curl -X POST https://auth.interactor.com/api/v1/admin/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "admin@yourcompany.com",
    "password": "SecureP@ssw0rd!",
    "org_name": "your-company"
  }'
```

| Field | Required | Default | Description |
|-------|----------|---------|-------------|
| `email` | Yes | — | Administrator email |
| `password` | Yes | — | Min 12 chars, uppercase, lowercase, number, special char |
| `org_name` | No | Derived from email | Organization slug (3-50 chars, lowercase, hyphens, starts with letter) |
| `app_name` | No | `"default-app"` | Name for the auto-created application |

Response (201):
```json
{
  "message": "Registration successful. Please check your email to verify your account.",
  "admin_id": "adm_abc123",
  "organization": {
    "id": "org_uuid",
    "name": "your-company"
  },
  "application": {
    "id": "app_uuid",
    "name": "default-app",
    "client_id": "app_xyz789",
    "client_secret": "sec_STORE_THIS_SECURELY"
  }
}
```

> **Important:** Save the `client_secret` immediately — it is only shown once.

> **Note:** `verification_token` is included in the response in development mode or if email delivery fails.

## 2. Verify Email

Click the link in your verification email, or call:

```bash
curl "https://auth.interactor.com/api/v1/admin/verify-email?token=YOUR_TOKEN"
```

If you didn't receive the email:

```bash
curl -X POST https://auth.interactor.com/api/v1/admin/resend-verification \
  -H "Content-Type: application/json" \
  -d '{"email": "admin@yourcompany.com"}'
```

## 3. Login

```bash
curl -X POST https://auth.interactor.com/api/v1/admin/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "admin@yourcompany.com",
    "password": "SecureP@ssw0rd!"
  }'
```

Response:
```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIs...",
  "refresh_token": "eyJhbGciOiJSUzI1NiIs...",
  "token_type": "Bearer",
  "expires_in": 900
}
```

If MFA is enabled, see [MFA Login Flow](08-mfa.md#mfa-login-flow).

## 4. Get an Application Token

Your backend uses OAuth 2.0 client credentials to get an access token:

```bash
curl -X POST https://auth.interactor.com/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=app_xyz789&client_secret=sec_STORE_THIS_SECURELY"
```

Response:
```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIs...",
  "token_type": "Bearer",
  "expires_in": 900,
  "scope": "interactor:read interactor:write"
}
```

The app token contains an `org` claim with your organization name.

## 5. Use the Token

```bash
curl https://core.interactor.com/api/v1/some-endpoint \
  -H "Authorization: Bearer <app_access_token>"
```

## Token Refresh

Access tokens expire after 15 minutes. Admin and user tokens have refresh tokens:

```bash
# Administrator
curl -X POST https://auth.interactor.com/api/v1/admin/refresh \
  -H "Content-Type: application/json" \
  -d '{"refresh_token": "eyJhbGciOi..."}'

# User
curl -X POST https://auth.interactor.com/api/v1/users/refresh \
  -H "Content-Type: application/json" \
  -d '{"refresh_token": "eyJhbGciOi..."}'
```

Application tokens don't have refresh tokens — request a new one via client credentials when expired.
