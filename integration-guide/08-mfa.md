# Multi-Factor Authentication (MFA)

Administrators can enable TOTP-based MFA for additional security. All setup/management endpoints require `Authorization: Bearer <admin_jwt>`.

---

## Enable MFA

### Step 1: Start Setup

```
POST /api/v1/admin/mfa/enable
```

Response:
```json
{
  "secret": "BASE32SECRET",
  "otpauth_uri": "otpauth://totp/AccountServer:admin@company.com?secret=...&issuer=AccountServer",
  "message": "Scan the QR code with your authenticator app, then verify with a code."
}
```

Display a QR code from the `otpauth_uri` for the admin to scan with their authenticator app (Google Authenticator, Authy, etc.).

| Error | Status | Description |
|-------|--------|-------------|
| `MFA is already enabled` | 400 | MFA was already set up |

### Step 2: Verify Setup

```
POST /api/v1/admin/mfa/verify
```

Request:
```json
{"code": "123456"}
```

Response:
```json
{
  "message": "MFA enabled successfully",
  "recovery_codes": [
    "abcd-1234-efgh",
    "ijkl-5678-mnop",
    "..."
  ]
}
```

> **Important:** Save the recovery codes securely. They are one-time-use backup codes for when the authenticator app is unavailable.

| Error | Status | Description |
|-------|--------|-------------|
| `MFA is already enabled` | 400 | Already verified |
| `No MFA setup in progress` | 400 | Must call enable first |
| `Invalid verification code` | 400 | Wrong TOTP code |

---

## MFA Login Flow

When MFA is enabled, the login endpoint returns a challenge instead of tokens.

### Step 1: Login (returns challenge)

```
POST /api/v1/admin/login
```

Response:
```json
{
  "mfa_required": true,
  "session_token": "sess_abc123..."
}
```

### Step 2: Complete with TOTP code

```
POST /api/v1/admin/login/mfa
```

Request:
```json
{
  "session_token": "sess_abc123...",
  "code": "123456"
}
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

| Error | Status | Description |
|-------|--------|-------------|
| `Invalid MFA code or session` | 401 | Wrong code or expired session |

The same flow applies to user login (`POST /api/v1/users/login` → `POST /api/v1/users/login/mfa`).

---

## Disable MFA

```
POST /api/v1/admin/mfa/disable
```

Request:
```json
{"code": "123456"}
```

Requires a valid TOTP code to confirm the action.

Response:
```json
{"message": "MFA disabled successfully"}
```

| Error | Status | Description |
|-------|--------|-------------|
| `MFA is not enabled` | 400 | MFA was not active |
| `Invalid verification code` | 400 | Wrong TOTP code |

---

## Regenerate Recovery Codes

```
POST /api/v1/admin/mfa/recovery-codes
```

Request:
```json
{"code": "123456"}
```

Requires a valid TOTP code to authorize regeneration. Previous recovery codes are invalidated.

Response:
```json
{
  "recovery_codes": [
    "abcd-1234-efgh",
    "ijkl-5678-mnop",
    "..."
  ]
}
```

| Error | Status | Description |
|-------|--------|-------------|
| `MFA is not enabled` | 400 | MFA must be active first |
| `Invalid verification code` | 400 | Wrong TOTP code |

---

## Endpoint Summary

| Action | Method | Endpoint | Auth |
|--------|--------|----------|------|
| Start MFA Setup | POST | `/api/v1/admin/mfa/enable` | Admin JWT |
| Verify MFA Setup | POST | `/api/v1/admin/mfa/verify` | Admin JWT |
| Disable MFA | POST | `/api/v1/admin/mfa/disable` | Admin JWT |
| Regenerate Recovery Codes | POST | `/api/v1/admin/mfa/recovery-codes` | Admin JWT |
| Admin MFA Login | POST | `/api/v1/admin/login/mfa` | None (session_token) |
| User MFA Login | POST | `/api/v1/users/login/mfa` | None (session_token) |
