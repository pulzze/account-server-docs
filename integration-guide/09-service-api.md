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
| Validate Token | POST | `/internal/validate` | App JWT |
| Check App Access | POST | `/internal/check-app-access` | App JWT |
