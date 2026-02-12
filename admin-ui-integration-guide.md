# Admin UI Integration Guide

## Building Admin Interfaces with Account Server Authentication

**Version:** 2.0.0
**Last Updated:** 2026-02-11

---

## Overview

This guide explains how to build an admin interface for your application that uses Account Server for administrator authentication. Account Server supports two approaches:

| Approach | Recommended For | Description |
|----------|-----------------|-------------|
| **SSO Redirect** (Recommended) | Browser-based admin UIs | Redirect to Account Server login page |
| **API-Based** | CLI tools, automation, testing | Forward credentials via API |

**We strongly recommend the SSO redirect approach for all admin UIs.** Benefits include:

1. **Single login UI** - No need to build login/MFA forms in your app
2. **Credentials stay secure** - Passwords only entered on Account Server
3. **Automatic MFA handling** - Account Server manages the entire MFA flow
4. **Consistent experience** - Admins see familiar login across all services
5. **Less code to maintain** - Your app only handles the OAuth callback

---

## SSO Redirect Approach (Recommended)

### Architecture

```
Admin Browser              Your App              Account Server
     │                        │                        │
     ├─ Visit /admin/login ──>│                        │
     │                        │                        │
     │                        ├── Redirect ───────────>│
     │                        │   /oauth/admin/authorize│
     │                        │   ?client_id=...       │
     │                        │   &redirect_uri=...    │
     │                        │   &code_challenge=...  │
     │                        │                        │
     │<───────────────────────┼────────────────────────│
     │                        │                        │
     │  [Enter credentials on Account Server]          │
     │  [Complete MFA if enabled]                      │
     │                        │                        │
     │────────────────────────┼───────────────────────>│
     │                        │                        │
     │                        │<── Redirect ───────────│
     │<───────────────────────│   /admin/callback      │
     │                        │   ?code=xxx&state=yyy  │
     │                        │                        │
     │                        ├── POST /oauth/admin/token ─>│
     │                        │   {code, code_verifier}│
     │                        │                        │
     │                        │<── {access_token} ─────│
     │                        │                        │
     │                    [Create local session]       │
     │                        │                        │
     │<── Set session cookie ─│                        │
     │    Redirect to /admin  │                        │
```

### Prerequisites

1. **Register your application** in Account Server
2. **Enable admin OAuth** for your application
3. **Configure admin redirect URIs** whitelist
4. Get your `client_id` and `client_secret`

### Application Setup

Contact your organization admin to configure your application:

```bash
# Required settings on Account Server
admin_oauth_enabled: true
admin_redirect_uris: [
  "https://your-app.com/admin/callback",
  "http://localhost:4000/admin/callback"  # Development
]
```

### Environment Variables

```bash
# Account Server URL
ACCOUNT_SERVER_URL=https://auth.interactor.com

# Your registered application credentials
ADMIN_CLIENT_ID=app_xxxxx
ADMIN_CLIENT_SECRET=sec_xxxxx

# Callback URL (must be in admin_redirect_uris whitelist)
ADMIN_CALLBACK_URL=https://your-app.com/admin/callback
```

### Implementation

#### 1. Login Route - Redirect to Account Server

When an admin visits `/admin/login`, redirect them to Account Server:

```javascript
// GET /admin/login
app.get('/admin/login', (req, res) => {
  // If already logged in, redirect to dashboard
  if (req.session.admin) {
    return res.redirect('/admin');
  }

  // Generate PKCE challenge
  const codeVerifier = crypto.randomBytes(32).toString('base64url');
  const codeChallenge = crypto
    .createHash('sha256')
    .update(codeVerifier)
    .digest('base64url');

  // Generate state for CSRF protection
  const state = crypto.randomBytes(32).toString('base64url');

  // Store in session for callback validation
  req.session.oauth = { codeVerifier, state };

  // Build authorization URL
  const params = new URLSearchParams({
    client_id: process.env.ADMIN_CLIENT_ID,
    redirect_uri: process.env.ADMIN_CALLBACK_URL,
    response_type: 'code',
    state: state,
    code_challenge: codeChallenge,
    code_challenge_method: 'S256'
  });

  res.redirect(`${process.env.ACCOUNT_SERVER_URL}/oauth/admin/authorize?${params}`);
});
```

#### 2. Callback Route - Exchange Code for Token

Handle the OAuth callback from Account Server:

```javascript
// GET /admin/callback
app.get('/admin/callback', async (req, res) => {
  const { code, state, error, error_description } = req.query;

  // Handle errors from Account Server
  if (error) {
    console.error(`OAuth error: ${error} - ${error_description}`);
    return res.redirect('/admin/login?error=auth_failed');
  }

  // Validate state (CSRF protection)
  if (state !== req.session.oauth?.state) {
    return res.redirect('/admin/login?error=invalid_state');
  }

  const codeVerifier = req.session.oauth.codeVerifier;
  delete req.session.oauth;

  try {
    // Exchange code for token
    const tokenResponse = await fetch(
      `${process.env.ACCOUNT_SERVER_URL}/oauth/admin/token`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          grant_type: 'authorization_code',
          code: code,
          redirect_uri: process.env.ADMIN_CALLBACK_URL,
          client_id: process.env.ADMIN_CLIENT_ID,
          client_secret: process.env.ADMIN_CLIENT_SECRET,
          code_verifier: codeVerifier
        })
      }
    );

    if (!tokenResponse.ok) {
      console.error('Token exchange failed:', await tokenResponse.text());
      return res.redirect('/admin/login?error=token_failed');
    }

    const { access_token } = await tokenResponse.json();

    // Extract admin info from JWT (without verification - AS already verified)
    const adminInfo = jwt.decode(access_token);

    // Create local session
    const sessionToken = await createAdminSession({
      adminId: adminInfo.sub,
      email: adminInfo.email,
      name: adminInfo.name,
      ipAddress: req.ip,
      userAgent: req.headers['user-agent']
    });

    // Set session cookie
    res.cookie('admin_session', sessionToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 24 * 60 * 60 * 1000 // 24 hours
    });

    res.redirect('/admin');

  } catch (error) {
    console.error('Callback error:', error);
    res.redirect('/admin/login?error=internal');
  }
});
```

#### 3. Logout Route

Logout is handled locally (no redirect needed):

```javascript
// DELETE /admin/logout or POST /admin/logout
app.post('/admin/logout', async (req, res) => {
  const token = req.cookies.admin_session;

  if (token) {
    await deleteAdminSession(token);
  }

  res.clearCookie('admin_session');
  res.redirect('/admin/login');
});
```

### JWT Token Structure

Account Server issues admin SSO tokens with these claims:

```json
{
  "sub": "adm_xxxxx",
  "email": "admin@example.com",
  "name": "Admin Name",
  "type": "admin",
  "client_id": "app_xxxxx",
  "iss": "https://auth.interactor.com",
  "aud": ["app_xxxxx"],
  "exp": 1234567890,
  "iat": 1234567800
}
```

### Complete Example (Node.js/Express)

```javascript
const express = require('express');
const session = require('express-session');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');

const app = express();

app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false
}));

// Login - redirect to Account Server
app.get('/admin/login', (req, res) => {
  if (req.session.admin) {
    return res.redirect('/admin');
  }

  const codeVerifier = crypto.randomBytes(32).toString('base64url');
  const codeChallenge = crypto.createHash('sha256').update(codeVerifier).digest('base64url');
  const state = crypto.randomBytes(32).toString('base64url');

  req.session.oauth = { codeVerifier, state };

  const params = new URLSearchParams({
    client_id: process.env.ADMIN_CLIENT_ID,
    redirect_uri: process.env.ADMIN_CALLBACK_URL,
    response_type: 'code',
    state,
    code_challenge: codeChallenge,
    code_challenge_method: 'S256'
  });

  res.redirect(`${process.env.ACCOUNT_SERVER_URL}/oauth/admin/authorize?${params}`);
});

// OAuth callback
app.get('/admin/callback', async (req, res) => {
  const { code, state, error } = req.query;

  if (error || state !== req.session.oauth?.state) {
    return res.redirect('/admin/login?error=auth_failed');
  }

  try {
    const tokenResponse = await fetch(`${process.env.ACCOUNT_SERVER_URL}/oauth/admin/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        grant_type: 'authorization_code',
        code,
        redirect_uri: process.env.ADMIN_CALLBACK_URL,
        client_id: process.env.ADMIN_CLIENT_ID,
        client_secret: process.env.ADMIN_CLIENT_SECRET,
        code_verifier: req.session.oauth.codeVerifier
      })
    });

    delete req.session.oauth;

    if (!tokenResponse.ok) {
      return res.redirect('/admin/login?error=token_failed');
    }

    const { access_token } = await tokenResponse.json();
    const adminInfo = jwt.decode(access_token);

    // Create local session (implement based on your database)
    const sessionToken = await createAdminSession(adminInfo, req);

    res.cookie('admin_session', sessionToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 24 * 60 * 60 * 1000
    });

    res.redirect('/admin');
  } catch (err) {
    res.redirect('/admin/login?error=internal');
  }
});

// Logout
app.post('/admin/logout', async (req, res) => {
  if (req.cookies.admin_session) {
    await deleteAdminSession(req.cookies.admin_session);
  }
  res.clearCookie('admin_session');
  res.redirect('/admin/login');
});

// Protected admin routes
app.use('/admin', requireAdmin, adminRouter);
```

### Complete Example (Elixir/Phoenix)

```elixir
# lib/my_app_web/controllers/admin_auth_controller.ex
defmodule MyAppWeb.AdminAuthController do
  use MyAppWeb, :controller

  alias MyApp.Auth.AdminOAuthClient
  alias MyApp.AdminSession
  alias MyAppWeb.Plugs.AdminSessionAuth

  def redirect_to_sso(conn, _params) do
    # If already logged in, redirect to dashboard
    if conn.assigns[:current_admin] do
      redirect(conn, to: ~p"/admin")
    else
      state = generate_state()
      {code_verifier, code_challenge} = generate_pkce()

      conn =
        conn
        |> put_session(:oauth_state, state)
        |> put_session(:oauth_code_verifier, code_verifier)

      authorize_url = AdminOAuthClient.build_authorize_url(
        state: state,
        code_challenge: code_challenge
      )

      redirect(conn, external: authorize_url)
    end
  end

  def callback(conn, %{"code" => code, "state" => state}) do
    stored_state = get_session(conn, :oauth_state)
    code_verifier = get_session(conn, :oauth_code_verifier)

    if state != stored_state do
      conn
      |> clear_oauth_session()
      |> put_flash(:error, "Invalid state")
      |> redirect(to: ~p"/admin/login")
    else
      case AdminOAuthClient.exchange_code(code, code_verifier) do
        {:ok, admin_info} ->
          create_session_and_redirect(conn, admin_info)
        {:error, _} ->
          conn
          |> clear_oauth_session()
          |> put_flash(:error, "Authentication failed")
          |> redirect(to: ~p"/admin/login")
      end
    end
  end

  def callback(conn, %{"error" => _error}) do
    conn
    |> clear_oauth_session()
    |> put_flash(:error, "Authentication failed")
    |> redirect(to: ~p"/admin/login")
  end

  defp create_session_and_redirect(conn, admin_info) do
    case AdminSession.create_session(admin_info) do
      {:ok, token, session} ->
        admin = %{
          id: session.id,
          admin_id: admin_info.admin_id,
          email: admin_info.email,
          name: admin_info[:name]
        }

        conn
        |> clear_oauth_session()
        |> AdminSessionAuth.log_in_admin(admin, token)
        |> redirect(to: ~p"/admin")
      {:error, _} ->
        conn
        |> clear_oauth_session()
        |> put_flash(:error, "Session creation failed")
        |> redirect(to: ~p"/admin/login")
    end
  end

  defp clear_oauth_session(conn) do
    conn
    |> delete_session(:oauth_state)
    |> delete_session(:oauth_code_verifier)
  end

  defp generate_state do
    :crypto.strong_rand_bytes(32) |> Base.url_encode64(padding: false)
  end

  defp generate_pkce do
    verifier = :crypto.strong_rand_bytes(32) |> Base.url_encode64(padding: false)
    challenge = :crypto.hash(:sha256, verifier) |> Base.url_encode64(padding: false)
    {verifier, challenge}
  end
end
```

```elixir
# lib/my_app/auth/admin_oauth_client.ex
defmodule MyApp.Auth.AdminOAuthClient do
  alias MyApp.Auth.JWT

  def build_authorize_url(opts) do
    base_url = account_server_url()
    client_id = admin_client_id()
    redirect_uri = admin_callback_url()

    query = URI.encode_query(%{
      client_id: client_id,
      redirect_uri: redirect_uri,
      response_type: "code",
      state: opts[:state],
      code_challenge: opts[:code_challenge],
      code_challenge_method: "S256"
    })

    "#{base_url}/oauth/admin/authorize?#{query}"
  end

  def exchange_code(code, code_verifier) do
    url = "#{account_server_url()}/oauth/admin/token"

    body = %{
      grant_type: "authorization_code",
      code: code,
      redirect_uri: admin_callback_url(),
      client_id: admin_client_id(),
      client_secret: admin_client_secret(),
      code_verifier: code_verifier
    }

    case Req.post(url, json: body) do
      {:ok, %{status: 200, body: %{"access_token" => token}}} ->
        extract_admin_info(token)
      _ ->
        {:error, :token_exchange_failed}
    end
  end

  defp extract_admin_info(token) do
    case JWT.peek_claims(token) do
      {:ok, claims} ->
        {:ok, %{
          admin_id: claims["sub"],
          email: claims["email"],
          name: claims["name"],
          access_token: token
        }}
      {:error, reason} ->
        {:error, {:invalid_token, reason}}
    end
  end

  defp account_server_url do
    Application.get_env(:my_app, :admin_auth)[:account_server_url] ||
      System.get_env("ACCOUNT_SERVER_URL")
  end

  defp admin_client_id do
    Application.get_env(:my_app, :admin_auth)[:client_id] ||
      System.get_env("ADMIN_CLIENT_ID")
  end

  defp admin_client_secret do
    Application.get_env(:my_app, :admin_auth)[:client_secret] ||
      System.get_env("ADMIN_CLIENT_SECRET")
  end

  defp admin_callback_url do
    Application.get_env(:my_app, :admin_auth)[:callback_url] ||
      System.get_env("ADMIN_CALLBACK_URL")
  end
end
```

```elixir
# Router
scope "/admin", MyAppWeb do
  pipe_through [:browser, :admin_session]

  get "/login", AdminAuthController, :redirect_to_sso
  get "/callback", AdminAuthController, :callback
  delete "/logout", AdminSessionController, :delete
end
```

---

## API Reference - Admin OAuth Endpoints

### GET /oauth/admin/authorize

Initiates admin OAuth flow. Redirects to login UI.

**Query Parameters:**

| Parameter | Required | Description |
|-----------|----------|-------------|
| `client_id` | Yes | Your application's client ID |
| `redirect_uri` | Yes | Callback URL (must be whitelisted) |
| `response_type` | Yes | Must be `code` |
| `state` | Recommended | CSRF protection token |
| `code_challenge` | Recommended | PKCE challenge (Base64-URL encoded) |
| `code_challenge_method` | With PKCE | `S256` (recommended) or `plain` |

**Example:**
```
GET /oauth/admin/authorize
  ?client_id=app_xxxxx
  &redirect_uri=https://your-app.com/admin/callback
  &response_type=code
  &state=random-csrf-token
  &code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
  &code_challenge_method=S256
```

**Success Response:**
Redirects to login page, then back to `redirect_uri?code=xxx&state=yyy`

**Error Response:**
Redirects to `redirect_uri?error=xxx&error_description=yyy`

### POST /oauth/admin/token

Exchanges authorization code for access token.

**Request Body:**

```json
{
  "grant_type": "authorization_code",
  "code": "auth-code-from-callback",
  "redirect_uri": "https://your-app.com/admin/callback",
  "client_id": "app_xxxxx",
  "client_secret": "sec_xxxxx",
  "code_verifier": "pkce-verifier-string"
}
```

**Success Response (200):**

```json
{
  "access_token": "eyJ...",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

**Error Responses:**

- `400` - Invalid request (missing parameters)
- `401` - Invalid client credentials
- `401` - Invalid or expired authorization code
- `401` - PKCE verification failed

---

## Security Considerations

### PKCE is Required

Always use PKCE with S256 for authorization code flow:

```javascript
// Generate PKCE values
const codeVerifier = crypto.randomBytes(32).toString('base64url');
const codeChallenge = crypto.createHash('sha256').update(codeVerifier).digest('base64url');
```

### State Parameter

Always use the state parameter to prevent CSRF attacks:

```javascript
const state = crypto.randomBytes(32).toString('base64url');
req.session.oauthState = state;

// In callback:
if (req.query.state !== req.session.oauthState) {
  return res.status(400).send('Invalid state');
}
```

### Redirect URI Whitelisting

Only whitelisted redirect URIs are accepted. Always register both:
- Production URL: `https://your-app.com/admin/callback`
- Development URL: `http://localhost:PORT/admin/callback`

### Token Lifetime

- Authorization codes expire in **5 minutes** and are single-use
- Access tokens are for one-time admin info extraction (not for API calls)
- Your app should create its own session after receiving the token

---

## Alternative: API-Based Authentication

For CLI tools, automated testing, or scenarios where redirect-based flow isn't suitable, you can use API-based authentication. **This approach requires handling credentials in your code.**

### When to Use API-Based Approach

- Command-line admin tools
- Automated testing
- Service-to-service authentication
- Scripts that need admin access

### API Endpoints

#### POST /api/v1/admin/login

```json
{
  "email": "admin@example.com",
  "password": "password123"
}
```

**Success (200):**
```json
{
  "access_token": "eyJ...",
  "refresh_token": "eyJ...",
  "expires_in": 900
}
```

**MFA Required (200):**
```json
{
  "mfa_required": true,
  "session_token": "temp-token"
}
```

#### POST /api/v1/admin/login/mfa

```json
{
  "session_token": "temp-token",
  "code": "123456"
}
```

### Application Permission Verification

With API-based auth, you must manually verify the admin has access to your application:

```javascript
// Get admin's organizations
const orgsResponse = await fetch(`${ACCOUNT_SERVER_URL}/api/v1/admin/orgs`, {
  headers: { 'Authorization': `Bearer ${accessToken}` }
});

// Check if admin's org owns your app
for (const org of organizations) {
  const appResponse = await fetch(
    `${ACCOUNT_SERVER_URL}/api/v1/admin/orgs/${org.name}/applications/${YOUR_APP_CLIENT_ID}`,
    { headers: { 'Authorization': `Bearer ${accessToken}` } }
  );
  if (appResponse.ok) {
    // Admin has permission
  }
}
```

**Note:** With SSO redirect approach, Account Server automatically verifies the admin has permission to access your application before issuing the authorization code.

---

## Session Management

### Session Token Storage

Never store raw session tokens:

```javascript
// Good: Store hash
const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
await db.adminSessions.create({ tokenHash, adminId, ... });

// Bad: Store raw token
await db.adminSessions.create({ token: rawToken, ... }); // DON'T
```

### Session Validation Middleware

```javascript
async function requireAdmin(req, res, next) {
  const token = req.cookies.admin_session;
  if (!token) {
    return res.redirect('/admin/login');
  }

  const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
  const session = await db.adminSessions.findOne({ where: { tokenHash } });

  if (!session || session.expiresAt < new Date()) {
    res.clearCookie('admin_session');
    return res.redirect('/admin/login');
  }

  req.admin = {
    id: session.adminId,
    email: session.adminEmail,
    name: session.adminName
  };

  next();
}
```

### Database Schema

```sql
CREATE TABLE admin_sessions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  token_hash VARCHAR(64) NOT NULL UNIQUE,
  admin_id VARCHAR(255) NOT NULL,
  admin_email VARCHAR(255) NOT NULL,
  admin_name VARCHAR(255),
  expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
  ip_address VARCHAR(45),
  user_agent TEXT,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_admin_sessions_token_hash ON admin_sessions(token_hash);
CREATE INDEX idx_admin_sessions_expires_at ON admin_sessions(expires_at);
```

---

## Deployment Checklist

- [ ] Register your application in Account Server
- [ ] Enable admin OAuth for your application
- [ ] Configure admin redirect URIs whitelist
- [ ] Set environment variables:
  - `ACCOUNT_SERVER_URL`
  - `ADMIN_CLIENT_ID`
  - `ADMIN_CLIENT_SECRET`
  - `ADMIN_CALLBACK_URL`
- [ ] Run database migration (create `admin_sessions` table)
- [ ] Test SSO login flow in development
- [ ] Test SSO login flow in staging/production
- [ ] Set up session cleanup job (optional)
- [ ] Configure monitoring for auth failures

---

## Troubleshooting

### "Invalid redirect URI"

- Verify `ADMIN_CALLBACK_URL` matches exactly what's in `admin_redirect_uris`
- Check protocol (http vs https)
- Check port number

### "Invalid client"

- Verify `ADMIN_CLIENT_ID` is correct
- Confirm application has `admin_oauth_enabled: true`
- Check application isn't revoked

### "Invalid state"

- State parameter doesn't match session
- Session may have expired or been cleared
- Check session middleware configuration

### "Token exchange failed"

- Verify `ADMIN_CLIENT_SECRET` is correct
- Check authorization code hasn't expired (5 minute TTL)
- Ensure code hasn't been used (single-use)
- Verify PKCE code_verifier matches original code_challenge

### Admin can't log in

- Verify admin account exists in Account Server
- Check admin has permission to your application (organization membership)
- Confirm account is active

---

## Migration from API-Based to SSO

If you're currently using the API-based approach with your own login form:

1. **Create new routes:**
   - `GET /admin/login` → redirect to Account Server
   - `GET /admin/callback` → handle OAuth callback

2. **Keep existing session management** - your session table/logic stays the same

3. **Remove login form** - no longer needed

4. **Update environment variables:**
   - Add `ADMIN_CLIENT_SECRET`
   - Add `ADMIN_CALLBACK_URL`

5. **Register callback URL** in Account Server admin redirect URIs

6. **Test thoroughly** before removing old login code

---

## Support

- API Reference: See [API Reference](./api-reference.md)
- Issues: Contact your organization administrator
