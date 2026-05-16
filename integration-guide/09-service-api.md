# Service API

Internal endpoints for service-to-service operations. These endpoints require `Authorization: Bearer <app_jwt>` (application token via client credentials).

---

## Validate Token

```
POST /internal/validate
```

Validate any Account Server JWT and retrieve the associated claims. Used by backend services to verify tokens without performing local JWKS validation.

Request:
```json
{
  "token": "eyJhbGciOiJSUzI1NiIs..."
}
```

### Response: Admin Token

```json
{
  "valid": true,
  "type": "admin",
  "admin_id": "adm_abc123",
  "email": "admin@acme.com",
  "scopes": ["*"],
  "expires_at": 1705312200
}
```

### Response: App Token

```json
{
  "valid": true,
  "type": "app",
  "client_id": "app_xyz789",
  "org": "acme-corp",
  "scopes": ["interactor:read", "interactor:write"],
  "expires_at": 1705312200
}
```

### Response: User Token

```json
{
  "valid": true,
  "type": "user",
  "user_id": "usr_def456",
  "username": "johndoe",
  "org": "acme-corp",
  "scopes": ["openid", "profile"],
  "expires_at": 1705312200
}
```

### Optional `include` Parameter

A comma-separated list of additional fields to return:

| Value | Effect | Token types |
|-------|--------|-------------|
| `teams` | Adds the user's active team memberships to the response | `user` only |

The parameter is opt-in to keep the hot validate path cheap for callers that don't need extras. Unknown values and values not meaningful for the token type are silently ignored.

Request with includes:
```json
{
  "token": "eyJhbGciOiJSUzI1NiIs...",
  "include": "teams"
}
```

Response (user token, `include=teams`):
```json
{
  "valid": true,
  "type": "user",
  "user_id": "usr_def456",
  "username": "johndoe",
  "org": "acme-corp",
  "scopes": ["openid", "profile"],
  "expires_at": 1705312200,
  "teams": [
    { "team_id": "550e8400-e29b-41d4-a716-446655440000", "role": "author" },
    { "team_id": "660e8400-e29b-41d4-a716-446655440001", "role": "member" }
  ]
}
```

Only **active** team memberships are included; archived teams are excluded.

### Active Team Context Validation

End-user apps signal the user's current team selection via the `X-Active-Team-Id` header (see [Teams §Active Team Context](11-teams.md#active-team-context)). The active team is intentionally **not** part of the JWT — it can change mid-session without re-issuing tokens.

Pattern for backend services that need to honor `X-Active-Team-Id`:

1. Extract the user JWT from the incoming request (`Authorization: Bearer <jwt>`).
2. Read the inbound `X-Active-Team-Id` header.
3. Call `POST /internal/validate?include=teams` with the user JWT.
4. Confirm the inbound `team_id` is in the response's `teams` array; otherwise fall back to user-scope (treat as no team context).

```bash
curl -X POST https://auth.interactor.com/internal/validate \
  -H "Authorization: Bearer <app_jwt>" \
  -H "Content-Type: application/json" \
  -d '{"token": "<user_jwt>", "include": "teams"}'
```

### Error Responses

| Response | Status | When |
|----------|--------|------|
| `{"valid": false, "error": "token_expired"}` | 401 | Token has expired |
| `{"valid": false, "error": "invalid_token"}` | 401 | Token is malformed or has invalid signature |
| `{"valid": false, "error": "admin_inactive"}` | 401 | Admin account suspended |
| `{"valid": false, "error": "app_inactive_or_revoked"}` | 401 | Application deactivated |
| `{"valid": false, "error": "user_inactive"}` | 401 | User account suspended |
| `{"error": "missing_token"}` | 400 | No token provided |

---

## Check App Access

```
POST /internal/check-app-access
```

Check whether an administrator has access to a specific application. Used by services that need to verify admin permissions before allowing configuration changes.

Request:
```json
{
  "admin_id": "adm_abc123",
  "client_id": "app_xyz789"
}
```

### Response: Has Access (Owner)

```json
{
  "has_access": true,
  "role": "owner",
  "permissions": ["read", "write", "delete", "admin"],
  "organization_id": "org_uuid",
  "organization_name": "acme-corp"
}
```

### Response: Has Access (Member)

```json
{
  "has_access": true,
  "role": "member",
  "permissions": ["read", "write"],
  "organization_id": "org_uuid",
  "organization_name": "acme-corp"
}
```

### Response: No Access

```json
{
  "has_access": false,
  "reason": "no_permission",
  "message": "Administrator does not have permission for this application"
}
```

| Error | Status | Description |
|-------|--------|-------------|
| `missing_parameters` | 400 | Missing `admin_id` or `client_id` |

---

## Endpoint Summary

| Action | Method | Endpoint | Auth |
|--------|--------|----------|------|
| Validate Token | POST | `/internal/validate[?include=teams]` | App JWT |
| Check App Access | POST | `/internal/check-app-access` | App JWT |
