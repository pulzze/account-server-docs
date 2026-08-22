# Reference

Error codes, rate limits, JWT verification, and best practices.

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

## JWT Verification

Your applications should validate JWTs locally using the JWKS endpoint. This is faster than calling the Account Server on every request.

### JWKS Endpoint

```
GET /.well-known/jwks.json
```

Returns the JSON Web Key Set for verifying token signatures. Cached with `Cache-Control: public, max-age=3600`.

### Token Claims by Type

Every token carries `iss` (`https://auth.interactor.com`), `iat` and `exp`;
access and refresh tokens also carry `jti`; ID tokens do not.

`aud` names the audiences a token was minted for, and it is derived one of two
ways:

- **Tokens issued for a specific OAuth client** — admin SSO, and access and ID
  tokens from the authorization-code flow — carry that application's
  `client_id`, plus any extra audiences configured on the application. The
  `client_id` is always present.
- **Tokens issued without a client** — admin login, client credentials, user
  login — carry the platform audience registry: the list of Interactor services
  that accept Account Server tokens. It is configuration rather than a fixed
  list, and it gains entries as services are added.

Account Server does not check `aud` on tokens presented to it — the claim
describes who a token was minted for, and checking it is yours to do if you want
to. Every audience below is a superset of what that token type carried before:
audience lists only ever gain entries, never lose them, so **no action is
required on your side**. If you do check, check that the audience you care
about is **present in** `aud` rather than pinning the exact list, and don't
treat an unfamiliar entry as a failure.

**Administrator Token (`type: "admin"`):**

| Claim | Description |
|-------|-------------|
| `sub` | Administrator ID (`adm_*`) |
| `type` | `"admin"` |
| `email` | Administrator email |
| `scopes` | Granted scopes |
| `aud` | From `/oauth/admin/token` (SSO): your `client_id` plus the application's extra audiences. From `/api/v1/admin/login`: the platform audience registry |

**Administrator Refresh Token (`type: "admin_refresh"`):**

| Claim | Description |
|-------|-------------|
| `sub` | Administrator ID (`adm_*`) |
| `type` | `"admin_refresh"` |
| `client_id` | The client the token was issued to |
| `aud` | Same as the admin SSO token it was issued alongside |

Returned by `/oauth/admin/token` and presented back to it with
`grant_type=refresh_token`. `aud` and `client_id` are new — this token carried
neither before — and redemption is unchanged, so refresh tokens issued earlier
still work.

**Application Token (`type: "app"`):**

| Claim | Description |
|-------|-------------|
| `sub` | Client ID (`app_*`) |
| `type` | `"app"` |
| `client_id` | Application client ID |
| `org` | Organization name |
| `scopes` | Granted scopes |
| `aud` | The platform audience registry — a client credentials token is not bound to one service |

**User Token (`type: "user"`):**

| Claim | Description |
|-------|-------------|
| `sub` | User ID (`usr_*`) |
| `type` | `"user"` |
| `org` | Organization name |
| `username` | Username |
| `scopes` | Granted scopes |
| `aud` | From the OIDC authorization-code flow: the application's `client_id` plus its extra audiences. From `/users/login` or SAML: the platform audience registry |

ID token claims, including when `aud` is a string and when it is an array, are
in [OAuth / OIDC](07-oauth-oidc.md#id-token-claims).

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
