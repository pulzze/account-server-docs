# Account Server Integration Guide

**Version:** 1.3.0
**Last Updated:** 2026-01-20

---

## Quick Reference

All endpoints use the base URL: `https://auth.interactor.com/api/v1`

| Action | Method | Endpoint | Required Fields | Optional Fields |
|--------|--------|----------|-----------------|-----------------|
| Register | POST | `/auth/register` | `email`, `password` | `redirect_uri`, `organization_name` |
| Login | POST | `/auth/login` | `email`, `password` | |
| MFA Login | POST | `/auth/login/mfa` | `mfa_token`, `code` | |
| Refresh Token | POST | `/auth/refresh` | `refresh_token` | |
| Logout | POST | `/auth/logout` | | `refresh_token` |
| Verify Email | GET/POST | `/auth/verify-email` | `token` | |
| Resend Verification | POST | `/auth/resend-verification` | `email` | `redirect_uri` |
| Request Password Reset | POST | `/auth/password/reset-request` | `email` | `redirect_uri` |
| Reset Password | POST | `/auth/password/reset` | `token`, `password` | `success_redirect_uri` |
| Change Password | POST | `/auth/password/change` | `current_password`, `new_password` | |

> **Note:** Missing required fields will return a 400 Bad Request with a `missing_required_fields` error code listing which fields are missing.

---

## Overview

The Account Server is the **central identity provider** for your internal application suite. It enables Single Sign-On (SSO) across all your applications - when a user logs into one app, their JWT works across all apps that trust the Account Server.

### Who This Guide Is For

This guide is for **your internal development team** building applications that use Account Server for user authentication.

> **Building a third-party integration with Interactor?** See the [Interactor Integration Guide](../../interactor/docs/integration-guide.md) instead - you'll use OAuth Client Credentials to authenticate your backend service.

### What Account Server Provides

- **User Registration & Login**: Email/password authentication with email verification
- **JWT Tokens**: RS256-signed tokens verified via JWKS endpoint
- **SSO Across Your Apps**: One user identity works across all your internal apps
- **MFA**: Optional TOTP-based multi-factor authentication
- **Password Management**: Reset flows, password change, requirements enforcement

### Base URL

```
Production: https://auth.interactor.com/api/v1
```

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        YOUR APPLICATION SUITE                                │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌───────────────┐   ┌───────────────┐   ┌───────────────┐                  │
│  │   App A       │   │   App B       │   │   App C       │                  │
│  │   (Web)       │   │   (Mobile)    │   │   (Dashboard) │                  │
│  │               │   │               │   │               │                  │
│  │ Validates JWT │   │ Validates JWT │   │ Validates JWT │                  │
│  │ via JWKS      │   │ via JWKS      │   │ via JWKS      │                  │
│  └───────┬───────┘   └───────┬───────┘   └───────┬───────┘                  │
│          │                   │                   │                           │
│          │         ┌─────────┴─────────┐         │                           │
│          │         │                   │         │                           │
│          └─────────┤  Account Server   ├─────────┘                           │
│                    │                   │                                     │
│                    │  - User accounts  │                                     │
│                    │  - Login/Register │                                     │
│                    │  - JWT issuance   │                                     │
│                    │  - JWKS endpoint  │                                     │
│                    └───────────────────┘                                     │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘

User logs into App A → Gets JWT → Same JWT works in App B and App C
```

---

## Quick Start

### 1. User Registration

Your app's registration form calls the Account Server API:

```bash
curl -X POST https://auth.interactor.com/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "SecureP@ssw0rd!"
  }'
```

**Optional Fields:**
- `organization_name`: Company or organization name (string, max 255 chars)

**Password Requirements:**
- Minimum 12 characters
- At least one uppercase letter
- At least one lowercase letter
- At least one number
- At least one special character

**Response:**
```json
{
  "data": {
    "account_id": "acc_abc123",
    "email": "user@example.com",
    "organization_name": null,
    "status": "pending_verification",
    "message": "Please check your email to verify your account"
  }
}
```

### 2. Email Verification

Users receive a verification email and click the link. When they click it:

- **Default behavior**: Account Server displays a simple HTML success page confirming verification, then the user can close the tab and log into your app
- **With `redirect_uri`**: If you provide a `redirect_uri` during registration, users are redirected there with `?status=success` appended

**Registration with redirect:**
```bash
curl -X POST https://auth.interactor.com/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "SecureP@ssw0rd!",
    "redirect_uri": "https://myapp.com/verified"
  }'
```

After clicking the email link, the user would be redirected to `https://myapp.com/verified?status=success`.

**Resend verification:**
```bash
curl -X POST https://auth.interactor.com/api/v1/auth/resend-verification \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com"}'
```

You can also include a `redirect_uri` when resending:
```bash
curl -X POST https://auth.interactor.com/api/v1/auth/resend-verification \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "redirect_uri": "https://myapp.com/verified"
  }'
```

### 3. User Login

```bash
curl -X POST https://auth.interactor.com/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "SecureP@ssw0rd!"
  }'
```

**Success Response:**
```json
{
  "data": {
    "access_token": "eyJhbGciOiJSUzI1NiIs...",
    "refresh_token": "eyJhbGciOiJSUzI1NiIs...",
    "token_type": "Bearer",
    "expires_in": 900
  }
}
```

**MFA Required Response:**
```json
{
  "data": {
    "mfa_required": true,
    "mfa_token": "mfa_session_token"
  }
}
```

If MFA is enabled, complete login with:
```bash
curl -X POST https://auth.interactor.com/api/v1/auth/login/mfa \
  -H "Content-Type: application/json" \
  -d '{
    "mfa_token": "mfa_session_token",
    "code": "123456"
  }'
```

### 4. Token Refresh

Access tokens expire after 15 minutes. Use the refresh token to get a new one:

```bash
curl -X POST https://auth.interactor.com/api/v1/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"refresh_token": "eyJhbGciOiJSUzI1NiIs..."}'
```

### 5. Logout

```bash
curl -X POST https://auth.interactor.com/api/v1/auth/logout \
  -H "Authorization: Bearer <access_token>" \
  -H "Content-Type: application/json" \
  -d '{"refresh_token": "eyJhbGciOiJSUzI1NiIs..."}'
```

---

## JWT Verification in Your Apps

Your applications should validate JWTs locally using the JWKS endpoint. This is fast and doesn't require calling Account Server on every request.

### JWKS Endpoint

```bash
curl https://auth.interactor.com/.well-known/jwks.json
```

**Response:**
```json
{
  "keys": [
    {
      "kty": "RSA",
      "kid": "key_2026_01",
      "use": "sig",
      "alg": "RS256",
      "n": "...",
      "e": "AQAB"
    }
  ]
}
```

### Token Claims

| Claim | Description |
|-------|-------------|
| `sub` | Account ID (`acc_abc123`) |
| `iss` | Issuer (`https://auth.interactor.com`) |
| `aud` | Audience (service-specific) |
| `exp` | Expiration timestamp |
| `iat` | Issued at timestamp |

### Example: Elixir/Phoenix Verification

```elixir
defmodule MyApp.Auth do
  @jwks_url "https://auth.interactor.com/.well-known/jwks.json"

  def verify_token(token) do
    with {:ok, jwks} <- fetch_jwks(),
         {:ok, claims} <- JOSE.JWT.verify(jwks, token) do
      {:ok, claims}
    end
  end

  defp fetch_jwks do
    # Cache this - don't fetch on every request
    case Cachex.get(:jwks_cache, "keys") do
      {:ok, nil} ->
        {:ok, %{body: body}} = HTTPoison.get(@jwks_url)
        jwks = Jason.decode!(body)
        Cachex.put(:jwks_cache, "keys", jwks, ttl: :timer.hours(1))
        {:ok, jwks}
      {:ok, jwks} ->
        {:ok, jwks}
    end
  end
end
```

### Example: Node.js Verification

```typescript
import jwt from 'jsonwebtoken';
import jwksClient from 'jwks-rsa';

const client = jwksClient({
  jwksUri: 'https://auth.interactor.com/.well-known/jwks.json',
  cache: true,
  rateLimit: true
});

function getKey(header, callback) {
  client.getSigningKey(header.kid, (err, key) => {
    const signingKey = key?.getPublicKey();
    callback(err, signingKey);
  });
}

export function verifyToken(token: string): Promise<any> {
  return new Promise((resolve, reject) => {
    jwt.verify(token, getKey, {
      issuer: 'https://auth.interactor.com'
    }, (err, decoded) => {
      if (err) reject(err);
      else resolve(decoded);
    });
  });
}
```

---

## Password Management

### Change Password (Authenticated)

```bash
curl -X POST https://auth.interactor.com/api/v1/auth/password/change \
  -H "Authorization: Bearer <access_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "current_password": "OldP@ssw0rd!",
    "new_password": "NewP@ssw0rd!"
  }'
```

### Request Password Reset

```bash
curl -X POST https://auth.interactor.com/api/v1/auth/password/reset-request \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com"}'
```

**With client redirect (for custom UI):**
```bash
curl -X POST https://auth.interactor.com/api/v1/auth/password/reset-request \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "redirect_uri": "https://myapp.com/reset-password"
  }'
```

When `redirect_uri` is provided, the email link will point to your app instead of the Account Server's built-in form. The token is appended as a query parameter: `https://myapp.com/reset-password?token=abc123`

### Reset Password with Token

```bash
curl -X POST https://auth.interactor.com/api/v1/auth/password/reset \
  -H "Content-Type: application/json" \
  -d '{
    "token": "reset_token_from_email",
    "password": "NewP@ssw0rd!"
  }'
```

**With success redirect:**
```bash
curl -X POST https://auth.interactor.com/api/v1/auth/password/reset \
  -H "Content-Type: application/json" \
  -d '{
    "token": "reset_token_from_email",
    "password": "NewP@ssw0rd!",
    "success_redirect_uri": "https://myapp.com/login?reset=success"
  }'
```

**Response with redirect:**
```json
{
  "data": {
    "message": "Password reset successfully",
    "redirect_uri": "https://myapp.com/login?reset=success"
  }
}
```

### Client-Side Password Reset Flow

If you want to provide a custom password reset UI:

1. **Request reset with redirect:**
   ```
   POST /api/v1/auth/password/reset-request
   Body: { "email": "user@example.com", "redirect_uri": "https://myapp.com/reset-password" }
   ```

2. **User receives email** with link to your app: `https://myapp.com/reset-password?token=abc123`

3. **Your app displays a password form** and collects the new password

4. **Submit the new password:**
   ```
   POST /api/v1/auth/password/reset
   Body: { "token": "abc123", "password": "NewP@ssw0rd!", "success_redirect_uri": "https://myapp.com/login" }
   ```

5. **On success**, redirect the user to the `redirect_uri` from the response (or handle as needed)

> **Note:** Both `redirect_uri` and `success_redirect_uri` are validated against the `ALLOWED_REDIRECT_DOMAINS` configuration. Requests with unauthorized domains will be silently ignored (to prevent enumeration attacks).

---

## Multi-Factor Authentication (MFA)

### Enable MFA

```bash
curl -X POST https://auth.interactor.com/api/v1/account/mfa/enable \
  -H "Authorization: Bearer <access_token>"
```

**Response:**
```json
{
  "data": {
    "secret": "base64_encoded_secret",
    "otpauth_uri": "otpauth://totp/Interactor:user@example.com?secret=...&issuer=Interactor"
  }
}
```

Display the `otpauth_uri` as a QR code for the user to scan with their authenticator app.

### Verify MFA Setup

After user adds to their authenticator, verify with a code:

```bash
curl -X POST https://auth.interactor.com/api/v1/account/mfa/verify \
  -H "Authorization: Bearer <access_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "secret": "base64_encoded_secret",
    "code": "123456"
  }'
```

**Response includes recovery codes:**
```json
{
  "data": {
    "mfa_enabled": true,
    "recovery_codes": [
      "ABCD-1234-EFGH",
      "IJKL-5678-MNOP"
    ],
    "message": "MFA enabled successfully. Save your recovery codes in a safe place."
  }
}
```

> **Important:** Display recovery codes to the user and ask them to save them securely.

### Disable MFA

```bash
curl -X POST https://auth.interactor.com/api/v1/account/mfa/disable \
  -H "Authorization: Bearer <access_token>" \
  -H "Content-Type: application/json" \
  -d '{"password": "UserP@ssw0rd!"}'
```

### Regenerate Recovery Codes

```bash
curl -X POST https://auth.interactor.com/api/v1/account/mfa/recovery-codes \
  -H "Authorization: Bearer <access_token>" \
  -H "Content-Type: application/json" \
  -d '{"password": "UserP@ssw0rd!"}'
```

---

## Account Management

### Get Account Info

```bash
curl https://auth.interactor.com/api/v1/account \
  -H "Authorization: Bearer <access_token>"
```

**Response:**
```json
{
  "data": {
    "account_id": "acc_abc123",
    "email": "user@example.com",
    "organization_name": null,
    "status": "active",
    "mfa_enabled": true,
    "created_at": "2026-01-01T00:00:00Z"
  }
}
```

### Update Account

You can set or update the optional `organization_name` field:

```bash
curl -X PATCH https://auth.interactor.com/api/v1/account \
  -H "Authorization: Bearer <access_token>" \
  -H "Content-Type: application/json" \
  -d '{"organization_name": "My Company"}'
```

---

## Error Handling

All errors follow a consistent format:

```json
{
  "error": {
    "code": "error_code",
    "message": "Human-readable message"
  }
}
```

### Common Error Codes

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `invalid_credentials` | 401 | Wrong email or password |
| `email_not_verified` | 403 | Account email not verified |
| `account_suspended` | 403 | Account has been suspended |
| `account_closed` | 403 | Account has been closed |
| `invalid_token` | 401 | Token is invalid or expired |
| `token_expired` | 401 | Token has expired |
| `invalid_code` | 400 | Invalid MFA code |
| `mfa_already_enabled` | 400 | MFA is already enabled |
| `mfa_not_enabled` | 400 | MFA is not enabled |
| `invalid_password` | 401 | Invalid password (for MFA disable/recovery) |
| `validation_error` | 422 | Request validation failed |
| `rate_limited` | 429 | Too many requests |

### Rate Limits

| Endpoint | Limit |
|----------|-------|
| `/auth/login` | 5 per minute per IP |
| `/auth/register` | 3 per hour per IP |
| `/auth/password/reset-request` | 3 per hour per email |
| Authenticated endpoints | 100 per minute per account |

---

## API Reference

### Public Endpoints (No Auth Required)

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/auth/register` | Create new account |
| POST | `/auth/login` | Login with email/password |
| POST | `/auth/login/mfa` | Complete MFA login |
| POST | `/auth/refresh` | Refresh access token |
| GET | `/auth/verify-email` | Verify email (from link) |
| POST | `/auth/verify-email` | Verify email (programmatic) |
| POST | `/auth/resend-verification` | Resend verification email |
| POST | `/auth/password/reset-request` | Request password reset |
| POST | `/auth/password/reset` | Reset password with token |
| GET | `/.well-known/jwks.json` | Get public keys for JWT verification |

### Authenticated Endpoints (Bearer Token Required)

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/auth/logout` | Revoke current session |
| POST | `/auth/password/change` | Change password |
| GET | `/account` | Get account info |
| PATCH | `/account` | Update account |
| POST | `/account/mfa/enable` | Start MFA setup |
| POST | `/account/mfa/verify` | Complete MFA setup |
| POST | `/account/mfa/disable` | Disable MFA |
| POST | `/account/mfa/recovery-codes` | Regenerate recovery codes |

---

## Troubleshooting

### Common Mistakes

**Wrong password reset endpoint:**
- Incorrect: `/auth/forgot-password` (does not exist)
- Correct: `/auth/password/reset-request`

**Missing required fields:**
- Registration requires `email` and `password`
- `organization_name` is optional

**Password requirements:**
- Minimum 12 characters
- At least one uppercase letter
- At least one lowercase letter
- At least one number
- At least one special character

### "Invalid credentials" on login
- Verify email and password are correct
- Check if the account email is verified
- Ensure password meets requirements

### "Token expired" errors
- Access tokens expire after 15 minutes
- Use the refresh token to get a new access token
- Refresh tokens expire after 7 days - user must log in again

### "Rate limited" errors
- Wait before retrying
- Implement exponential backoff
- Consider if you're making too many requests

### MFA codes not working
- Ensure the user's device time is synchronized (NTP)
- Codes are valid for 30 seconds
- Use a recovery code if they've lost access to their authenticator

### JWKS caching
- Cache JWKS responses (1 hour recommended)
- Handle key rotation gracefully (try all keys in the set)
- Refresh cache on signature verification failure
