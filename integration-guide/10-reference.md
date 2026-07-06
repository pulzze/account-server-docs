# Reference

Error codes, rate limits, health checks, JWT verification, and best practices.

---

## Error Handling

Account Server uses two error formats depending on context:

### Authentication Errors (flat format)

Most authentication and authorization errors return:
```json
{"error": "Human-readable error message"}
```

Examples:
- `{"error": "Invalid email or password"}` (401)
- `{"error": "Account is not active. Please verify your email."}` (403)
- `{"error": "Invalid or expired verification token"}` (400)

### Validation Errors (structured format)

Changeset validation errors return:
```json
{
  "error": {
    "code": "validation_error",
    "message": "Validation failed",
    "details": {
      "email": ["has already been taken"],
      "password": ["should be at least 12 character(s)"]
    }
  }
}
```

### OAuth Errors (RFC 6749)

OAuth endpoints return standard OAuth error format:
```json
{
  "error": "invalid_client",
  "error_description": "Client authentication failed"
}
```

### FallbackController Error Codes

| Input | Status | Response |
|-------|--------|----------|
| Changeset errors | 422 | `{"error": {"code": "validation_error", ...}}` |
| `:not_found` | 404 | `{"error": {"code": "not_found", "message": "Resource not found"}}` |
| `:unauthorized` | 401 | `{"error": {"code": "unauthorized", "message": "Unauthorized"}}` |
| `:forbidden` | 403 | `{"error": {"code": "forbidden", "message": "Forbidden"}}` |

---

## Rate Limits

| Endpoint | Limit |
|----------|-------|
| `/admin/login` | 5 per minute per IP |
| `/admin/register` | 3 per hour per IP |
| `/users/login` | 10 per minute per IP |
| `/oauth/token` | 30 per minute per client_id |
| Authenticated endpoints | 100 per minute per token |

Rate-limited responses return HTTP 429 with a `Retry-After` header.

---

## Health & Readiness

Account Server exposes health endpoints for load balancers, orchestrators, and uptime monitors. All three are unauthenticated. Every response includes a `docs_url` field pointing to the public documentation repo so operators can jump straight to the API docs from a probe.

| Endpoint | Purpose | Checks dependencies? |
|----------|---------|----------------------|
| `GET /health` | Legacy combined health (kept for backward compatibility) | No |
| `GET /health/live` | Liveness — is the process up? | No |
| `GET /health/ready` | Readiness — are downstream dependencies reachable? | Yes |

### GET /health (legacy)

Returns `200` when the process is running. Fields: `status` (`"ok"`), `timestamp`, `version`, and `docs_url`.

```json
{
  "status": "ok",
  "timestamp": "2026-07-06T12:00:00Z",
  "version": "1.4.0",
  "docs_url": "https://github.com/pulzze/account-server-docs"
}
```

### GET /health/live

Process-only liveness. Returns `200` as long as the application is running; it does **not** touch the database or other dependencies, so use it for orchestrator liveness probes. Fields: `status`, `check` (`"live"`), `service`, `version`, `docs_url`.

```json
{
  "status": "ok",
  "check": "live",
  "service": "account-server",
  "version": "1.4.0",
  "docs_url": "https://github.com/pulzze/account-server-docs"
}
```

### GET /health/ready

Dependency-aware readiness. Returns `200` with `status`, `check` (`"ready"`), `service`, and a `components` map when every dependency check passes. Use it for readiness probes and to gate traffic behind a load balancer.

```json
{
  "status": "ok",
  "check": "ready",
  "service": "account-server",
  "components": {
    "database": "ok"
  },
  "docs_url": "https://github.com/pulzze/account-server-docs"
}
```

When a component check fails, the endpoint returns `503` with `status: "not_ready"` and the failing component marked in `components`:

```json
{
  "status": "not_ready",
  "check": "ready",
  "service": "account-server",
  "components": {
    "database": "error"
  },
  "docs_url": "https://github.com/pulzze/account-server-docs"
}
```

---

## JWT Verification

Your applications should validate JWTs locally using the JWKS endpoint. This is faster than calling the Account Server on every request.

### JWKS Endpoint

```
GET /.well-known/jwks.json
```

Returns the JSON Web Key Set for verifying token signatures. Cached with `Cache-Control: public, max-age=3600`.

### Token Claims by Type

**Administrator Token (`type: "admin"`):**

| Claim | Description |
|-------|-------------|
| `sub` | Administrator ID (`adm_*`) |
| `type` | `"admin"` |
| `email` | Administrator email |
| `scopes` | Granted scopes |

**Application Token (`type: "app"`):**

| Claim | Description |
|-------|-------------|
| `sub` | Client ID (`app_*`) |
| `type` | `"app"` |
| `client_id` | Application client ID |
| `org` | Organization name |
| `scopes` | Granted scopes |

**User Token (`type: "user"`):**

| Claim | Description |
|-------|-------------|
| `sub` | User ID (`usr_*`) |
| `type` | `"user"` |
| `org` | Organization name |
| `username` | Username |
| `scopes` | Granted scopes |

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
    callback(err, key?.getPublicKey());
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

const claims = await verifyToken(token);
if (claims.type === 'app') {
  console.log('App:', claims.client_id, 'Org:', claims.org);
} else if (claims.type === 'user') {
  console.log('User:', claims.username, 'Org:', claims.org);
}
```

### Example: Python Verification

```python
import jwt
from jwt import PyJWKClient

jwks_client = PyJWKClient("https://auth.interactor.com/.well-known/jwks.json")

def verify_token(token: str) -> dict:
    signing_key = jwks_client.get_signing_key_from_jwt(token)
    return jwt.decode(
        token,
        signing_key.key,
        algorithms=["RS256"],
        issuer="https://auth.interactor.com"
    )
```

---

## Password Requirements

### Administrator Passwords
- Minimum 12 characters
- At least one uppercase letter
- At least one lowercase letter
- At least one number
- At least one special character

### User Passwords
- Minimum 8 characters
- At least one uppercase letter
- At least one lowercase letter
- At least one number
- At least one special character

---

## Best Practices

### Token Management

1. **Cache app tokens** — Don't request a new token for every API call
2. **Refresh proactively** — Refresh tokens before they expire (e.g., when < 60 seconds remaining)
3. **Handle expiration gracefully** — If a request fails with 401, refresh and retry

### Secret Storage

1. **Never hardcode secrets** — Use environment variables or secrets managers
2. **Rotate secrets periodically** — Use the rotate endpoint with the 24-hour grace period
3. **Separate apps per environment** — Don't share credentials between dev/staging/production

### User Management

1. **Usernames are per-org** — The same username can exist in different organizations
2. **Store user_id** — Reference users by `user_id`, not username
3. **User tokens are org-wide** — A user JWT is valid for all apps in the organization

---

## Troubleshooting

### "Invalid credentials" on login

- For admins: verify email/password are correct, check if email is verified
- For users: ensure you're providing the correct `org` (organization name, not ID)

### "Invalid token" errors

- Access tokens expire after 15 minutes
- Use refresh tokens (admin/user) or client credentials (app) to get new tokens
- Verify you're using the correct token type for the endpoint

### "Token type mismatch"

| Endpoint Pattern | Required Token |
|------------------|---------------|
| `/admin/*` | Admin JWT |
| `/admin/orgs/:org_name/*` | Admin JWT + org membership |
| `/orgs/:org_name/users/*` | Admin or App JWT |
| `/oauth/token` | Client credentials (not JWT) |
| `/internal/*` | App JWT |

### Application token not working

- Verify client_id and client_secret are correct
- Check that the application status is `active`
- Ensure the application has the required scopes

### "Forbidden" on organization operations

- Verify you're a member of the organization
- Some operations (delete org) require owner role
- Member operations on applications require per-app permissions
