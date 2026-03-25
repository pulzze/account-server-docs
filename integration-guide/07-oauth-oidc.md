# OAuth 2.0 / OIDC User Authentication

Account Server acts as an **Identity Provider (IdP)** for your applications, similar to Auth0 or Okta. This enables your users to authenticate through a hosted login page with support for:

- Username/password login
- Social login (Google, GitHub)

> **Recommended**: This is the preferred method for authenticating users in web applications, SPAs, and mobile apps. User credentials are handled entirely by Account Server, never touching your application servers.

---

## Prerequisites

Before using OAuth flows, configure your application:

1. **Enable Authorization Code grant** — Update your application's `grant_types` to include `"authorization_code"`
2. **Add redirect URIs** — Add your app's callback URL(s) via `redirect_uris`

```bash
curl -X PATCH https://auth.interactor.com/api/v1/admin/orgs/your-company/applications/app_xyz \
  -H "Authorization: Bearer <admin_jwt>" \
  -H "Content-Type: application/json" \
  -d '{
    "grant_types": ["client_credentials", "authorization_code"],
    "redirect_uris": ["https://yourapp.com/auth/callback"]
  }'
```

## Discovery Endpoints

| Endpoint | Purpose |
|----------|---------|
| `GET /oauth/authorize` | Start the OAuth flow (redirect users here) |
| `POST /oauth/token` | Exchange authorization code for tokens |
| `POST /oauth/revoke` | Revoke a token (RFC 7009) |
| `GET /.well-known/openid-configuration` | OIDC discovery document |
| `GET /.well-known/jwks.json` | Public keys for token verification |

## Social Providers Discovery

Check which social login providers are available for an application:

```
GET /api/v1/social/providers?client_id=app_xyz789
```

Response:
```json
{
  "providers": [
    {
      "id": "google",
      "name": "Google",
      "authorization_url": "https://accounts.google.com/o/oauth2/v2/auth"
    },
    {
      "id": "github",
      "name": "GitHub",
      "authorization_url": "https://github.com/login/oauth/authorize"
    }
  ]
}
```

No authentication required. Returns only providers enabled for the specified application.

---

## Integration Patterns

| Pattern | Best For | User Experience |
|---------|----------|-----------------|
| **Redirect Flow** | Traditional web apps, server-rendered apps | Full page redirect to login |
| **Popup Flow** | SPAs, modern web apps | Login opens in popup window |

Both patterns use the secure **Authorization Code** flow with optional PKCE.

---

## Pattern 1: Redirect Flow

```
Your App                    Account Server
   │                              │
   │  1. Redirect to /authorize   │
   │ ────────────────────────────►│
   │                              │
   │                    2. User logs in
   │                              │
   │  3. Redirect back with code  │
   │ ◄────────────────────────────│
   │                              │
   │  4. Exchange code for tokens │
   │ ────────────────────────────►│
   │                              │
   │  5. Return tokens            │
   │ ◄────────────────────────────│
```

### Step 1: Redirect to Authorization

```javascript
function startLogin() {
  const state = crypto.randomUUID();
  sessionStorage.setItem('oauth_state', state);

  const authUrl = new URL('https://auth.interactor.com/oauth/authorize');
  authUrl.searchParams.set('client_id', 'your_client_id');
  authUrl.searchParams.set('redirect_uri', 'https://yourapp.com/auth/callback');
  authUrl.searchParams.set('response_type', 'code');
  authUrl.searchParams.set('scope', 'openid profile email');
  authUrl.searchParams.set('state', state);

  window.location.href = authUrl.toString();
}
```

Authorization parameters:

| Param | Required | Description |
|-------|----------|-------------|
| `client_id` | Yes | Your application's client ID |
| `redirect_uri` | Yes | Must match a registered redirect URI |
| `response_type` | Yes | Must be `"code"` |
| `scope` | No | Space-separated scopes (e.g., `"openid profile email"`) |
| `state` | Recommended | CSRF protection token |
| `nonce` | No | For OIDC replay protection |
| `code_challenge` | No | PKCE challenge (recommended for public clients) |
| `code_challenge_method` | No | `"plain"` or `"S256"` |

### Step 2: Handle the Callback

After login, Account Server redirects to your `redirect_uri`:

```
https://yourapp.com/auth/callback?code=abc123&state=xyz789
```

### Step 3: Exchange Code for Tokens (Server-Side)

**Important:** The code exchange must happen on your backend to protect your client secret.

```bash
curl -X POST https://auth.interactor.com/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "client_id=your_client_id" \
  -d "client_secret=your_client_secret" \
  -d "code=abc123" \
  -d "redirect_uri=https://yourapp.com/auth/callback"
```

Response:
```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIs...",
  "id_token": "eyJhbGciOiJSUzI1NiIs...",
  "refresh_token": "eyJhbGciOiJSUzI1NiIs...",
  "token_type": "Bearer",
  "expires_in": 900
}
```

- `id_token` is included when `openid` scope was requested
- `refresh_token` is included when `offline_access` scope was requested

### Example: Express.js Backend

```javascript
app.get('/auth/callback', async (req, res) => {
  const { code, state } = req.query;

  const tokenResponse = await fetch('https://auth.interactor.com/oauth/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      client_id: process.env.OAUTH_CLIENT_ID,
      client_secret: process.env.OAUTH_CLIENT_SECRET,
      code,
      redirect_uri: 'https://yourapp.com/auth/callback'
    })
  });

  const tokens = await tokenResponse.json();
  req.session.accessToken = tokens.access_token;
  res.redirect('/dashboard');
});
```

---

## Pattern 2: Popup Flow

Login opens in a popup window, keeping users on your page.

### Frontend: Open Popup and Listen for Response

```javascript
function loginWithPopup() {
  const width = 500, height = 600;
  const left = window.screenX + (window.innerWidth - width) / 2;
  const top = window.screenY + (window.innerHeight - height) / 2;

  const state = crypto.randomUUID();
  sessionStorage.setItem('oauth_state', state);

  const authUrl = new URL('https://auth.interactor.com/oauth/authorize');
  authUrl.searchParams.set('client_id', 'your_client_id');
  authUrl.searchParams.set('redirect_uri', 'https://auth.interactor.com/oauth/callback/popup');
  authUrl.searchParams.set('response_type', 'code');
  authUrl.searchParams.set('scope', 'openid profile email');
  authUrl.searchParams.set('state', state);

  const popup = window.open(
    authUrl.toString(), 'oauth_login',
    `width=${width},height=${height},left=${left},top=${top}`
  );

  window.addEventListener('message', async function handler(event) {
    if (event.origin !== 'https://auth.interactor.com') return;

    const { code, state: returnedState, error } = event.data;
    if (returnedState !== sessionStorage.getItem('oauth_state')) return;

    window.removeEventListener('message', handler);
    sessionStorage.removeItem('oauth_state');

    if (error) { console.error('OAuth error:', error); return; }

    // Exchange code for tokens via your backend
    const response = await fetch('/api/auth/callback', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ code })
    });

    const { user } = await response.json();
    // Update UI with logged-in user
  });
}
```

---

## Token Revocation

```
POST /oauth/revoke
```

Request:
```json
{"token": "eyJhbGciOi..."}
```

Response: 200 OK with empty body `{}`.

Follows RFC 7009. Currently a no-op for short-lived JWTs but provides forward compatibility.

> **Note:** `/api/v1/oauth/revoke` also works as a legacy alias.

---

## OIDC Discovery

```
GET /.well-known/openid-configuration
```

Returns the standard OIDC discovery document including:

```json
{
  "issuer": "https://auth.interactor.com",
  "authorization_endpoint": "https://auth.interactor.com/oauth/authorize",
  "token_endpoint": "https://auth.interactor.com/oauth/token",
  "jwks_uri": "https://auth.interactor.com/.well-known/jwks.json",
  "revocation_endpoint": "https://auth.interactor.com/oauth/revoke",
  "response_types_supported": ["code"],
  "grant_types_supported": ["authorization_code", "client_credentials", "refresh_token"],
  "id_token_signing_alg_values_supported": ["RS256"],
  "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
  "scopes_supported": ["openid", "profile", "email", "offline_access", "interactor:read", "interactor:write", "service-knowledge-base:read", "service-knowledge-base:write"],
  "code_challenge_methods_supported": ["plain", "S256"]
}
```

---

## Social Login

When social login providers are enabled for your application, the Account Server login page automatically displays social login buttons. Users can login with username/password or sign in via Google/GitHub.

**Your integration code stays the same** — Account Server handles the social provider interaction and returns tokens in the same format.

### Enabling Social Login

1. Go to your application in the Account Server admin panel
2. Toggle on the desired social providers (Google, GitHub)
3. Optionally configure your own OAuth credentials (BYOC) for branded consent screens

---

## ID Token Claims

When using the `openid` scope, you receive an ID token:

```json
{
  "iss": "https://auth.interactor.com",
  "sub": "usr_abc123",
  "aud": "your_client_id",
  "exp": 1234567890,
  "iat": 1234567890,
  "org": "your-organization",
  "username": "johndoe",
  "email": "john@example.com"
}
```

---

## OAuth Scopes

| Scope | Description |
|-------|-------------|
| `openid` | Required for OIDC. Returns an ID token |
| `profile` | Access to username |
| `email` | Access to email address |
| `offline_access` | Include a refresh token |

---

## Security Best Practices

1. **Always validate the `state` parameter** to prevent CSRF attacks
2. **Exchange codes server-side** — Never expose your `client_secret` to the browser
3. **Use PKCE** for public clients (mobile apps, SPAs without a backend)
4. **Verify token signatures** using the JWKS endpoint
5. **Check the `aud` claim** matches your client_id
