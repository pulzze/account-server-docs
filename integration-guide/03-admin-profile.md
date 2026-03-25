# Administrator Profile

Endpoints for managing the authenticated administrator's profile. All require `Authorization: Bearer <admin_jwt>`.

---

## Get Profile

```
GET /api/v1/admin
```

Response:
```json
{
  "admin_id": "adm_abc123",
  "email": "admin@yourcompany.com",
  "email_verified": true,
  "status": "active",
  "mfa_enabled": false,
  "created_at": "2026-01-15T10:30:00Z"
}
```

## Update Profile

```
PATCH /api/v1/admin
```

Updates are validated at the schema level. Email changes require re-verification.

## Logout

```
POST /api/v1/admin/logout
```

Request (optional):
```json
{
  "refresh_token": "eyJhbGciOi..."
}
```

Response:
```json
{"message": "Logged out successfully"}
```

If `refresh_token` is provided, it is invalidated. The access token remains valid until expiry (stateless JWT).

## Change Password

```
POST /api/v1/admin/password/change
```

Request:
```json
{
  "current_password": "OldP@ssw0rd!",
  "new_password": "NewSecureP@ss1!"
}
```

Response:
```json
{"message": "Password changed successfully"}
```

| Error | Status | Description |
|-------|--------|-------------|
| `Current password is incorrect` | 401 | Wrong current password |
| Changeset errors | 422 | New password doesn't meet requirements |

## Password Reset (Public)

For administrators who forgot their password.

### Request Reset

```
POST /api/v1/admin/password/reset-request
```

Request:
```json
{"email": "admin@yourcompany.com"}
```

Response (always 200):
```json
{"message": "If the email exists, a password reset link will be sent."}
```

### Reset Password

```
POST /api/v1/admin/password/reset
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
{"message": "Password reset successfully"}
```

---

## Endpoint Summary

| Action | Method | Endpoint | Auth |
|--------|--------|----------|------|
| Get Profile | GET | `/api/v1/admin` | Admin JWT |
| Update Profile | PATCH | `/api/v1/admin` | Admin JWT |
| Logout | POST | `/api/v1/admin/logout` | Admin JWT |
| Change Password | POST | `/api/v1/admin/password/change` | Admin JWT |
| Request Password Reset | POST | `/api/v1/admin/password/reset-request` | None |
| Reset Password | POST | `/api/v1/admin/password/reset` | None |
| Resend Verification | POST | `/api/v1/admin/resend-verification` | None |
