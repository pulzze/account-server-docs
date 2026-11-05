# Quick Start

Minimal steps to go from zero to making authenticated API calls.

## 1. Register as an Administrator

Registration creates your admin account and first organization. It issues no application or credentials yet: those come once you confirm your email address (step 2).

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

Response (201):
```json
{
  "message": "Registration successful. Please check your email to verify your account.",
  "admin_id": "adm_abc123",
  "organization": {
    "id": "org_uuid",
    "name": "your-company"
  }
}
```

## 2. Verify Email

Click the link in your verification email. It opens a page that asks for the password you chose in step 1. Once you enter it:

- your address is confirmed;
- your organization's default application (`default-app`) is created;
- its `client_id` and `client_secret` are shown.

> **Important:** Save the `client_secret` immediately — it is only shown once.

Opening the link on its own confirms nothing, so a mail scanner that opens it first does no harm. A wrong password leaves the link usable.

To confirm from a script instead, send the token from the link together with the password:

```bash
curl -i -X POST https://auth.interactor.com/api/v1/admin/verify-email \
  -H "Content-Type: application/json" \
  -d '{"token": "YOUR_TOKEN", "password": "SecureP@ssw0rd!"}'
```

For a new sign-up the reply is a `302` to the page that shows the new application's credentials. Open that address in a browser within five minutes. Errors: `400 password_required`, `401 invalid_password`, or `400` for an unknown, expired or already used link.

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
