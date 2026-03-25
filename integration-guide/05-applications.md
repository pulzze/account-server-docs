# Applications

Applications are OAuth clients for your backend services. Each application gets a `client_id` and `client_secret` for authenticating via client credentials.

All endpoints require `Authorization: Bearer <admin_jwt>` and org membership.

---

## List Applications

```
GET /api/v1/admin/orgs/:org_name/applications
```

Owners see all applications. Members see only applications they have `read` permission for.

Response:
```json
{
  "applications": [
    {
      "id": "app_uuid",
      "client_id": "app_xyz789",
      "name": "production-backend",
      "display_name": "Production Backend",
      "description": "Main production server",
      "scopes": ["interactor:read", "interactor:write"],
      "status": "active",
      "application_type": "default",
      "redirect_uris": [],
      "grant_types": ["client_credentials"],
      "admin_redirect_uris": [],
      "admin_oauth_enabled": false,
      "last_used_at": "2026-01-20T14:00:00Z",
      "created_at": "2026-01-15T10:30:00Z"
    }
  ]
}
```

## Create Application

```
POST /api/v1/admin/orgs/:org_name/applications
```

Request:
```json
{
  "name": "production-backend",
  "display_name": "Production Backend",
  "description": "Main production server",
  "scopes": ["interactor:read", "interactor:write"]
}
```

Response (201):
```json
{
  "client_id": "app_xyz789",
  "client_secret": "sec_STORE_THIS_SECURELY",
  "name": "production-backend",
  "description": "Main production server",
  "scopes": ["interactor:read", "interactor:write"],
  "status": "active",
  "created_at": "2026-01-15T10:30:00Z"
}
```

> **Important:** The `client_secret` is only returned at creation time. Store it securely.

## Get Application

```
GET /api/v1/admin/orgs/:org_name/applications/:id
```

The `:id` parameter is the application's `client_id`.

Members require `read` permission. Returns the full application format (same as list items).

## Update Application

```
PATCH /api/v1/admin/orgs/:org_name/applications/:id
```

Members require `write` permission.

Updatable fields are grouped by category:

**General:**

| Field | Description |
|-------|-------------|
| `name` | Application slug |
| `display_name` | Display name |
| `description` | Description |
| `scopes` | Granted scopes array |

**OAuth (for user-facing apps):**

| Field | Description |
|-------|-------------|
| `redirect_uris` | Allowed redirect URIs for OAuth flows |
| `grant_types` | Allowed grant types (e.g., `["client_credentials", "authorization_code"]`) |

**Admin OAuth SSO:**

| Field | Description |
|-------|-------------|
| `admin_redirect_uris` | Allowed redirect URIs for admin SSO |
| `admin_oauth_enabled` | Enable admin OAuth SSO for this app |

## Rotate Client Secret

```
POST /api/v1/admin/orgs/:org_name/applications/:id/rotate-secret
```

Members require `write` permission.

Response:
```json
{
  "client_id": "app_xyz789",
  "client_secret": "sec_NEW_SECRET_VALUE",
  "message": "Secret rotated. The old secret will remain valid for 24 hours."
}
```

The old secret remains valid for 24 hours, allowing rolling deployments.

## Delete Application

```
DELETE /api/v1/admin/orgs/:org_name/applications/:id
```

Members require `delete` permission. Returns 204 No Content.

---

## Get an Application Token

Use OAuth 2.0 client credentials to authenticate your backend:

```
POST /oauth/token
```

Request (form-encoded):
```
grant_type=client_credentials
client_id=app_xyz789
client_secret=sec_YOUR_SECRET
```

Or with HTTP Basic Auth:
```bash
curl -X POST https://auth.interactor.com/oauth/token \
  -u "app_xyz789:sec_YOUR_SECRET" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials"
```

Optional: request specific scopes (subset of app's granted scopes):
```
grant_type=client_credentials&scope=interactor:read
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

The access token includes an `org` claim with your organization name.

> **Note:** `/api/v1/oauth/token` also works as a legacy alias.

---

## Available Scopes

| Scope | Description |
|-------|-------------|
| `interactor:read` | Read access to Interactor APIs |
| `interactor:write` | Write access to Interactor APIs |
| `service-knowledge-base:read` | Read access to Knowledge Base |
| `service-knowledge-base:write` | Write access to Knowledge Base |
| `openid` | Required for OIDC (returns ID token) |
| `profile` | Access to username |
| `email` | Access to email address |
| `offline_access` | Include a refresh token |

---

## Endpoint Summary

| Action | Method | Endpoint | Auth |
|--------|--------|----------|------|
| List Apps | GET | `/api/v1/admin/orgs/:org_name/applications` | Admin JWT + member |
| Create App | POST | `/api/v1/admin/orgs/:org_name/applications` | Admin JWT + member |
| Get App | GET | `/api/v1/admin/orgs/:org_name/applications/:id` | Admin JWT + read |
| Update App | PATCH | `/api/v1/admin/orgs/:org_name/applications/:id` | Admin JWT + write |
| Rotate Secret | POST | `/api/v1/admin/orgs/:org_name/applications/:id/rotate-secret` | Admin JWT + write |
| Delete App | DELETE | `/api/v1/admin/orgs/:org_name/applications/:id` | Admin JWT + delete |
| Get Token | POST | `/oauth/token` | Client credentials |
