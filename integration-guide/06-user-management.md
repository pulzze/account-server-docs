# User Management

Manage end users within your organization. Users authenticate with org + username + password and receive their own JWTs.

---

## Admin/App User Management

These endpoints let administrators and applications create, manage, and control user accounts. They require `Authorization: Bearer <admin_or_app_jwt>`.

For admin tokens, org membership is required. Members need per-application permissions (`read`, `write`, `delete`). Owners have implicit full access. App tokens have full access to users in their organization.

### List Users

```
GET /api/v1/orgs/:org_name/users
```

Query parameters:

| Param | Default | Description |
|-------|---------|-------------|
| `limit` | `100` | Page size |
| `offset` | `0` | Pagination offset |

Response:
```json
{
  "users": [
    {
      "user_id": "usr_abc123",
      "username": "johndoe",
      "email": "john@example.com",
      "email_verified": true,
      "status": "active",
      "mfa_enabled": false,
      "metadata": {"department": "Engineering"},
      "created_at": "2026-01-15T10:30:00Z"
    }
  ]
}
```

### Create User

```
POST /api/v1/orgs/:org_name/users
```

Request:
```json
{
  "username": "johndoe",
  "password": "Password123@",
  "email": "john@example.com",
  "metadata": {"department": "Engineering"}
}
```

**Password Requirements (User):**
- Minimum 8 characters
- At least one uppercase, one lowercase, one number, one special character

Response (201): Single user object (same format as list items).

### Get User

```
GET /api/v1/orgs/:org_name/users/:user_id
```

Members require `read` permission. Response: single user object.

### Update User

```
PATCH /api/v1/orgs/:org_name/users/:user_id
```

Members require `write` permission.

Only these fields can be updated:

| Field | Description |
|-------|-------------|
| `email` | User's email address |
| `metadata` | Arbitrary JSON metadata |

### Delete User

```
DELETE /api/v1/orgs/:org_name/users/:user_id
```

Members require `delete` permission. Returns 204 No Content.

### Change User Password (Admin-Initiated)

```
POST /api/v1/orgs/:org_name/users/:user_id/password/change
```

Members require `write` permission.

Request:
```json
{
  "new_password": "NewSecureP@ss1!"
}
```

Response:
```json
{"message": "Password changed successfully"}
```

> **Note:** This does NOT require the user's current password — it's an administrative override.

### Force Logout User

```
POST /api/v1/orgs/:org_name/users/:user_id/logout
```

Members require `write` permission.

Response:
```json
{"message": "User logged out from all sessions"}
```

Invalidates all the user's active refresh tokens.

---

## User Self-Registration

Allow end users to register directly, without admin intervention. These endpoints are **public** (no auth required).

### Register

```
POST /api/v1/orgs/:org_name/users/register
```

Request:
```json
{
  "email": "user@example.com",
  "password": "Password123@",
  "username": "janedoe"
}
```

| Field | Required | Description |
|-------|----------|-------------|
| `email` | Yes | User's email address |
| `password` | Yes | Must meet password requirements |
| `username` | Yes | Unique within the organization |
| `redirect_uri` | No | Where to redirect after email verification |

Response (201):
```json
{
  "message": "Registration successful. Please check your email to verify your account.",
  "user_id": "usr_def456"
}
```

> **Note:** `verification_token` is included in development mode or if email delivery fails.

| Error | Status | Description |
|-------|--------|-------------|
| `Organization not found` | 404 | Invalid org_name |
| Changeset errors | 422 | Validation failures (duplicate username, weak password, etc.) |

### Verify Email

```
GET /api/v1/orgs/:org_name/users/verify-email?token=TOKEN
```

Also accepts `POST`. Response:
```json
{"message": "Email verified successfully. You can now log in."}
```

If a `redirect_uri` was set during registration, redirects there instead.

### Resend Verification

```
POST /api/v1/orgs/:org_name/users/resend-verification
```

Request:
```json
{
  "email": "user@example.com"
}
```

| Field | Required | Description |
|-------|----------|-------------|
| `email` | Yes | User's email |
| `redirect_uri` | No | Where to redirect after verification |

Response (always 200, to prevent email enumeration):
```json
{"message": "If the email exists, a verification link will be sent."}
```

### Request Password Reset

```
POST /api/v1/orgs/:org_name/users/password/reset-request
```

Request:
```json
{
  "email": "user@example.com"
}
```

| Field | Required | Description |
|-------|----------|-------------|
| `email` | Yes | User's email |
| `redirect_uri` | No | Where to redirect from reset link |

Response (always 200):
```json
{"message": "If the email exists, a password reset link will be sent."}
```

### Reset Password

```
POST /api/v1/orgs/:org_name/users/password/reset
```

Request:
```json
{
  "token": "RESET_TOKEN_FROM_EMAIL",
  "password": "NewSecureP@ss1!"
}
```

Response:
```json
{"message": "Password reset successfully. You can now log in."}
```

---

## User Authentication

Public endpoints for end-user login and token management.

### Login

```
POST /api/v1/users/login
```

Request:
```json
{
  "org": "your-company",
  "username": "johndoe",
  "password": "Password123@"
}
```

All three fields are required.

Response (no MFA):
```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIs...",
  "refresh_token": "eyJhbGciOiJSUzI1NiIs...",
  "token_type": "Bearer",
  "expires_in": 900
}
```

Response (MFA enabled):
```json
{
  "mfa_required": true,
  "session_token": "sess_xyz..."
}
```

| Error | Status | Description |
|-------|--------|-------------|
| `Invalid credentials` | 401 | Wrong username or password |
| `User account is not active` | 403 | Account suspended or unverified |

### MFA Login

```
POST /api/v1/users/login/mfa
```

Request:
```json
{
  "session_token": "sess_xyz...",
  "code": "123456"
}
```

Response: Same token format as login.

### Refresh Token

```
POST /api/v1/users/refresh
```

Request:
```json
{
  "refresh_token": "eyJhbGciOiJSUzI1NiIs..."
}
```

Response: Same token format as login.

---

## User Identity Management

Authenticated users can view and manage their linked social identities. Requires `Authorization: Bearer <user_jwt>`.

### List Identities

```
GET /api/v1/users/me/identities
```

Response:
```json
{
  "identities": [
    {
      "id": "ident_uuid",
      "provider": "google",
      "provider_email": "john@gmail.com",
      "status": "active",
      "last_used_at": "2026-01-20T14:00:00Z",
      "linked_at": "2026-01-15T10:30:00Z"
    }
  ]
}
```

### Unlink Identity

```
DELETE /api/v1/users/me/identities/:id
```

Response:
```json
{"message": "Identity unlinked successfully"}
```

| Error | Status | Description |
|-------|--------|-------------|
| `Identity not found` | 404 | No identity with that ID for this user |
| `Cannot unlink last login method` | 400 | User must retain at least one way to authenticate |

---

## Endpoint Summary

| Action | Method | Endpoint | Auth |
|--------|--------|----------|------|
| **Admin/App Management** | | | |
| List Users | GET | `/api/v1/orgs/:org_name/users` | Admin/App JWT |
| Create User | POST | `/api/v1/orgs/:org_name/users` | Admin/App JWT |
| Get User | GET | `/api/v1/orgs/:org_name/users/:user_id` | Admin/App JWT |
| Update User | PATCH | `/api/v1/orgs/:org_name/users/:user_id` | Admin/App JWT |
| Delete User | DELETE | `/api/v1/orgs/:org_name/users/:user_id` | Admin/App JWT |
| Change Password | POST | `/api/v1/orgs/:org_name/users/:user_id/password/change` | Admin/App JWT |
| Force Logout | POST | `/api/v1/orgs/:org_name/users/:user_id/logout` | Admin/App JWT |
| **Self-Registration** | | | |
| Register | POST | `/api/v1/orgs/:org_name/users/register` | None |
| Verify Email | GET/POST | `/api/v1/orgs/:org_name/users/verify-email` | None |
| Resend Verification | POST | `/api/v1/orgs/:org_name/users/resend-verification` | None |
| Password Reset Request | POST | `/api/v1/orgs/:org_name/users/password/reset-request` | None |
| Password Reset | POST | `/api/v1/orgs/:org_name/users/password/reset` | None |
| **User Authentication** | | | |
| Login | POST | `/api/v1/users/login` | None |
| MFA Login | POST | `/api/v1/users/login/mfa` | None |
| Refresh Token | POST | `/api/v1/users/refresh` | None |
| **Identity Management** | | | |
| List Identities | GET | `/api/v1/users/me/identities` | User JWT |
| Unlink Identity | DELETE | `/api/v1/users/me/identities/:id` | User JWT |
