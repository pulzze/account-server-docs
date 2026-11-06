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

Asks to change the administrator's email address. It needs the account's current password, and the new address must be confirmed before the account uses it.

Request:
```json
{
  "email": "new-address@yourcompany.com",
  "current_password": "CurrentP@ssw0rd!"
}
```

Response (`202 Accepted`):
```json
{
  "admin_id": "adm_abc123",
  "email": "admin@yourcompany.com",
  "pending_email": "new-address@yourcompany.com",
  "message": "We sent a confirmation link to the new address. ..."
}
```

What happens next:
- The account keeps its current email until the change is confirmed. Sign-in, password resets and tokens all use the current address meanwhile.
- A confirmation link is sent to the new address. It opens a page that asks for the account's password; the email changes only when that page is sent with the right one. The link works for 24 hours, and stops working after 5 wrong passwords.
- The current address gets a notice that a change was requested. The notice has no link. Once the change is confirmed, the previous address gets a second notice.
- A newer request replaces an earlier one that is still waiting.
- To cancel a change that is still waiting, send `PATCH /api/v1/admin` with the account's current address (and `current_password`). Changing or resetting the password also cancels it.

Without `email`, or with the account's current address, the answer is `200` with `admin_id` and `email`, and the address does not change (with the current address, a change still waiting is cancelled).

Errors:

| Status | When |
|--------|------|
| `400` `current_password_required` | `email` sent without `current_password` |
| `401` | `current_password` is wrong |
| `403` | the account is not active |
| `422` | the address is invalid, or another administrator already has it |
| `429` | too many attempts: the account's current-password checks (shared with Change Password) or the emails to one address (shared with password-reset requests) |

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
