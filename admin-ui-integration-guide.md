# Admin UI Integration Guide

## Building Admin Interfaces with Account Server Authentication

**Version:** 1.0.0
**Last Updated:** 2026-01-23

---

## Overview

This guide explains how to build an admin interface for your application that uses Account Server for administrator authentication. This pattern allows you to:

1. **Delegate identity management** - Account Server handles admin accounts, passwords, and MFA
2. **Maintain independent sessions** - Your app controls session lifetime and behavior
3. **Enforce application permissions** - Only admins with access to your registered app can log in

### Architecture

```
┌─────────────────────┐
│  Your Admin UI      │
│  (Browser)          │
└──────────┬──────────┘
           │
           │ 1. Admin enters email/password
           ▼
┌─────────────────────┐
│  Your App Backend   │
│                     │
│  - Receives creds   │
│  - Calls Account    │
│    Server API       │
│  - Verifies app     │
│    permission       │
│  - Creates local    │
│    session          │
└──────────┬──────────┘
           │
           │ 2. Authenticate admin
           ▼
┌─────────────────────┐
│  Account Server     │
│                     │
│  - Validates creds  │
│  - Handles MFA      │
│  - Returns JWT      │
│  - Provides app     │
│    permission check │
└─────────────────────┘
```

---

## Prerequisites

Before integrating, you need:

1. **A registered application** in Account Server with a `client_id`
2. **Administrator accounts** created in Account Server with the `admin` role
3. **Application permissions** granted to admin accounts (via organization membership)

### Registering Your Application

Contact your organization admin to register your application in Account Server. You'll receive:
- `client_id` - Your application's unique identifier (UUID format)
- This is used to verify that admins have permission to access your specific application

---

## Authentication Flow

### Step 1: Admin Login Request

Your admin UI collects credentials and sends them to your backend:

```javascript
// Frontend: POST to your backend
const response = await fetch('/admin/login', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    email: 'admin@example.com',
    password: 'password123'
  })
});
```

### Step 2: Backend Authenticates with Account Server

Your backend calls the Account Server admin login endpoint:

```javascript
// Backend: Call Account Server
const authResponse = await fetch('https://auth.interactor.com/api/v1/admin/login', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    email: credentials.email,
    password: credentials.password
  })
});

const result = await authResponse.json();
```

### Step 3: Handle MFA (if enabled)

If the admin has MFA enabled, Account Server returns:

```json
{
  "mfa_required": true,
  "session_token": "temp-session-token-for-mfa"
}
```

Your app should:
1. Store the `session_token` temporarily
2. Prompt the admin for their TOTP code
3. Complete authentication with the MFA endpoint:

```javascript
// Complete MFA verification
const mfaResponse = await fetch('https://auth.interactor.com/api/v1/admin/login/mfa', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    session_token: storedSessionToken,
    code: totpCode
  })
});
```

### Step 4: Verify Application Permission

After successful authentication, verify the admin has access to your application:

```javascript
// Get admin's organizations
const orgsResponse = await fetch('https://auth.interactor.com/api/v1/admin/orgs', {
  headers: { 'Authorization': `Bearer ${accessToken}` }
});
const { organizations } = await orgsResponse.json();

// Check each org for your app permission
let hasPermission = false;
for (const org of organizations) {
  const appResponse = await fetch(
    `https://auth.interactor.com/api/v1/admin/orgs/${org.name}/applications/${YOUR_APP_CLIENT_ID}`,
    { headers: { 'Authorization': `Bearer ${accessToken}` } }
  );

  if (appResponse.ok) {
    hasPermission = true;
    break;
  }
}

if (!hasPermission) {
  throw new Error('Admin does not have permission to access this application');
}
```

### Step 5: Create Local Session

Once authenticated and authorized, create a session in your application:

```javascript
// Generate a secure session token
const sessionToken = crypto.randomBytes(32).toString('base64url');

// Store hashed token in your database
const tokenHash = crypto.createHash('sha256').update(sessionToken).digest('hex');

await db.adminSessions.create({
  tokenHash: tokenHash,
  adminId: jwtPayload.sub,
  adminEmail: jwtPayload.email,
  adminName: jwtPayload.name,
  expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000), // 24 hours
  ipAddress: request.ip,
  userAgent: request.headers['user-agent']
});

// Return session token to client (via secure cookie or response)
```

---

## Complete Authentication Flow Diagram

```
Admin              Your App              Account Server
  │                  │                        │
  ├─ Enter email ───>│                        │
  │   password       │                        │
  │                  │                        │
  │                  ├─ POST /api/v1/admin/login ─────────────>│
  │                  │ {email, password}                       │
  │                  │                                         │
  │                  │                    [Validate credentials]
  │                  │                                         │
  │                  │<── {access_token} or {mfa_required} ────│
  │                  │                                         │
  │  [If MFA required]                                         │
  │<── Show MFA form │                                         │
  │                  │                                         │
  ├─ Enter TOTP ────>│                                         │
  │                  │                                         │
  │                  ├─ POST /api/v1/admin/login/mfa ─────────>│
  │                  │ {session_token, code}                   │
  │                  │                                         │
  │                  │<── {access_token} ──────────────────────│
  │                  │                                         │
  │                  ├─ GET /api/v1/admin/orgs ────────────────>│
  │                  │ Authorization: Bearer token             │
  │                  │                                         │
  │                  │<── {organizations: [...]} ──────────────│
  │                  │                                         │
  │                  ├─ GET /api/v1/admin/orgs/{org}/          │
  │                  │     applications/{app_client_id} ──────>│
  │                  │                                         │
  │                  │<── {200 OK} or {404} ───────────────────│
  │                  │                                         │
  │              [Create local session]                        │
  │                  │                                         │
  │<── Set session ──│                                         │
  │    cookie        │                                         │
```

---

## JWT Token Structure

Account Server issues JWTs with these claims for admin authentication:

```json
{
  "sub": "admin-uuid",
  "email": "admin@example.com",
  "name": "Admin Name",
  "org": "organization-name",
  "role": "admin",
  "type": "user",
  "iss": "https://auth.interactor.com",
  "aud": ["interactor", "knowledge-base"],
  "exp": 1234567890,
  "iat": 1234567800
}
```

**Key claims for admin verification:**
- `role: "admin"` - Confirms admin role
- `sub` - Unique admin identifier (use this for your local records)
- `org` - Admin's primary organization

---

## API Reference

### POST /api/v1/admin/login

Authenticate an administrator.

**Request:**
```json
{
  "email": "admin@example.com",
  "password": "password123"
}
```

**Success Response (200):**
```json
{
  "access_token": "eyJ...",
  "refresh_token": "eyJ...",
  "expires_in": 900
}
```

**MFA Required Response (200):**
```json
{
  "mfa_required": true,
  "session_token": "temp-token-uuid"
}
```

**Error Responses:**
- `401` - Invalid credentials
- `403` - Account inactive (email not verified)

---

### POST /api/v1/admin/login/mfa

Complete MFA verification.

**Request:**
```json
{
  "session_token": "temp-token-uuid",
  "code": "123456"
}
```

**Success Response (200):**
```json
{
  "access_token": "eyJ...",
  "refresh_token": "eyJ...",
  "expires_in": 900
}
```

**Error Responses:**
- `401` - Invalid MFA code
- `401` - Session token expired

---

### GET /api/v1/admin/orgs

List organizations the admin belongs to.

**Headers:**
```
Authorization: Bearer <access_token>
```

**Response (200):**
```json
{
  "organizations": [
    {
      "name": "my-org",
      "display_name": "My Organization",
      "role": "admin"
    }
  ]
}
```

---

### GET /api/v1/admin/orgs/{org_name}/applications/{client_id}

Check if an application is registered under an organization.

**Headers:**
```
Authorization: Bearer <access_token>
```

**Response (200):** Application exists and admin has access
**Response (404):** Application not found or no access

---

## Configuration

### Environment Variables

Your application needs these configuration values:

```bash
# Account Server base URL
ACCOUNT_SERVER_URL=https://auth.interactor.com

# Your registered application's client ID
# Used to verify admin has permission to access your app
YOUR_APP_CLIENT_ID=your-app-uuid-here

# Session settings
ADMIN_SESSION_TTL=86400  # 24 hours in seconds
```

### Development Mode

For local development, you may want to skip authentication:

```bash
# WARNING: Only use in development!
ADMIN_AUTH_SKIP=true
```

When `ADMIN_AUTH_SKIP=true`, your app should allow any admin access without calling Account Server.

---

## Session Management Best Practices

### Token Storage

Never store raw session tokens in your database:

```javascript
// Good: Store hash
const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
await db.sessions.create({ tokenHash, ... });

// Bad: Store raw token
await db.sessions.create({ token: token, ... });  // DON'T DO THIS
```

### Session Validation

On each request, validate the session:

```javascript
async function validateAdminSession(token) {
  const tokenHash = crypto.createHash('sha256').update(token).digest('hex');

  const session = await db.adminSessions.findOne({
    where: { tokenHash }
  });

  if (!session) {
    return null; // Invalid token
  }

  if (session.expiresAt < new Date()) {
    await session.destroy(); // Clean up expired session
    return null;
  }

  return {
    adminId: session.adminId,
    email: session.adminEmail,
    name: session.adminName
  };
}
```

### Session Cleanup

Implement automatic cleanup of expired sessions:

```javascript
// Run periodically (e.g., daily cron job)
async function cleanupExpiredSessions() {
  await db.adminSessions.destroy({
    where: {
      expiresAt: { [Op.lt]: new Date() }
    }
  });
}
```

### Logout

When an admin logs out, delete their session:

```javascript
async function logout(token) {
  const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
  await db.adminSessions.destroy({ where: { tokenHash } });
}
```

### Force Logout All Sessions

To logout an admin from all devices:

```javascript
async function logoutAllSessions(adminId) {
  await db.adminSessions.destroy({
    where: { adminId }
  });
}
```

---

## Error Handling

### Common Scenarios

| Error | Cause | User Message |
|-------|-------|--------------|
| `invalid_credentials` | Wrong email/password | "Invalid email or password" |
| `account_inactive` | Email not verified | "Please verify your email first" |
| `mfa_required` | MFA enabled | Show MFA input form |
| `invalid_mfa_code` | Wrong TOTP code | "Invalid verification code" |
| `no_permission` | Admin lacks app access | "You don't have access to this application" |
| `session_expired` | Token or session expired | Redirect to login |

### Implementation Example

```javascript
async function handleLogin(email, password) {
  try {
    const result = await authenticateAdmin(email, password);

    if (result.mfaRequired) {
      return { type: 'mfa_required', sessionToken: result.sessionToken };
    }

    // Check app permission
    const hasPermission = await verifyAppPermission(result.accessToken);
    if (!hasPermission) {
      return { type: 'error', message: "You don't have access to this application" };
    }

    // Create session
    const session = await createAdminSession(result);
    return { type: 'success', session };

  } catch (error) {
    switch (error.code) {
      case 'INVALID_CREDENTIALS':
        return { type: 'error', message: 'Invalid email or password' };
      case 'ACCOUNT_INACTIVE':
        return { type: 'error', message: 'Please verify your email first' };
      default:
        return { type: 'error', message: 'Login failed. Please try again.' };
    }
  }
}
```

---

## Security Considerations

### 1. Always Verify App Permission

Don't skip the permission check. Without it, any Account Server admin could access your app:

```javascript
// REQUIRED: Always check permission
const hasPermission = await verifyAppPermission(accessToken);
if (!hasPermission) {
  throw new ForbiddenError();
}
```

### 2. Use Secure Session Cookies

Set appropriate cookie flags:

```javascript
res.cookie('admin_session', sessionToken, {
  httpOnly: true,      // Prevents JavaScript access
  secure: true,        // HTTPS only
  sameSite: 'strict',  // CSRF protection
  maxAge: 24 * 60 * 60 * 1000  // 24 hours
});
```

### 3. Log Security Events

Track admin access for audit purposes:

```javascript
await auditLog.create({
  event: 'admin_login',
  adminId: admin.id,
  adminEmail: admin.email,
  ipAddress: request.ip,
  userAgent: request.headers['user-agent'],
  timestamp: new Date()
});
```

### 4. Rate Limit Login Attempts

Protect against brute force attacks:

```javascript
const rateLimit = require('express-rate-limit');

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 attempts per window
  message: 'Too many login attempts. Please try again later.'
});

app.post('/admin/login', loginLimiter, loginHandler);
```

### 5. Don't Cache Permissions

Always verify permissions on login, not from cache. Organization membership can change:

```javascript
// Good: Check on every login
const hasPermission = await verifyAppPermission(accessToken);

// Bad: Use cached permission
const cachedPermission = await cache.get(`admin:${adminId}:permission`);
```

---

## Complete Backend Example (Node.js/Express)

```javascript
const express = require('express');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());

const ACCOUNT_SERVER_URL = process.env.ACCOUNT_SERVER_URL;
const YOUR_APP_CLIENT_ID = process.env.YOUR_APP_CLIENT_ID;

// Login endpoint
app.post('/admin/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    // Step 1: Authenticate with Account Server
    const authResponse = await fetch(`${ACCOUNT_SERVER_URL}/api/v1/admin/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password })
    });

    if (!authResponse.ok) {
      const error = await authResponse.json();
      return res.status(401).json({ error: error.error || 'Invalid credentials' });
    }

    const authResult = await authResponse.json();

    // Step 2: Check for MFA
    if (authResult.mfa_required) {
      return res.json({
        mfa_required: true,
        session_token: authResult.session_token
      });
    }

    // Step 3: Verify app permission
    const hasPermission = await verifyAppPermission(authResult.access_token);
    if (!hasPermission) {
      return res.status(403).json({
        error: 'You do not have permission to access this application'
      });
    }

    // Step 4: Create local session
    const session = await createSession(authResult.access_token, req);

    // Step 5: Set session cookie and redirect
    res.cookie('admin_session', session.token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 24 * 60 * 60 * 1000
    });

    res.json({ success: true, redirect: '/admin' });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
});

// MFA verification endpoint
app.post('/admin/login/mfa', async (req, res) => {
  const { session_token, code } = req.body;

  try {
    const mfaResponse = await fetch(`${ACCOUNT_SERVER_URL}/api/v1/admin/login/mfa`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ session_token, code })
    });

    if (!mfaResponse.ok) {
      return res.status(401).json({ error: 'Invalid verification code' });
    }

    const authResult = await mfaResponse.json();

    // Continue with permission check and session creation...
    const hasPermission = await verifyAppPermission(authResult.access_token);
    if (!hasPermission) {
      return res.status(403).json({
        error: 'You do not have permission to access this application'
      });
    }

    const session = await createSession(authResult.access_token, req);

    res.cookie('admin_session', session.token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 24 * 60 * 60 * 1000
    });

    res.json({ success: true, redirect: '/admin' });

  } catch (error) {
    console.error('MFA error:', error);
    res.status(500).json({ error: 'Verification failed' });
  }
});

// Logout endpoint
app.post('/admin/logout', async (req, res) => {
  const token = req.cookies.admin_session;

  if (token) {
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
    await db.adminSessions.destroy({ where: { tokenHash } });
  }

  res.clearCookie('admin_session');
  res.json({ success: true, redirect: '/admin/login' });
});

// Helper: Verify app permission
async function verifyAppPermission(accessToken) {
  // Skip check if no app client ID configured (development mode)
  if (!YOUR_APP_CLIENT_ID) {
    return true;
  }

  // Get admin's organizations
  const orgsResponse = await fetch(`${ACCOUNT_SERVER_URL}/api/v1/admin/orgs`, {
    headers: { 'Authorization': `Bearer ${accessToken}` }
  });

  if (!orgsResponse.ok) {
    return false;
  }

  const { organizations } = await orgsResponse.json();

  // Check each org for the app
  for (const org of organizations) {
    const appResponse = await fetch(
      `${ACCOUNT_SERVER_URL}/api/v1/admin/orgs/${org.name}/applications/${YOUR_APP_CLIENT_ID}`,
      { headers: { 'Authorization': `Bearer ${accessToken}` } }
    );

    if (appResponse.ok) {
      return true;
    }
  }

  return false;
}

// Helper: Create local session
async function createSession(accessToken, req) {
  const decoded = jwt.decode(accessToken);

  const token = crypto.randomBytes(32).toString('base64url');
  const tokenHash = crypto.createHash('sha256').update(token).digest('hex');

  await db.adminSessions.create({
    tokenHash,
    adminId: decoded.sub,
    adminEmail: decoded.email,
    adminName: decoded.name,
    expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000),
    ipAddress: req.ip,
    userAgent: req.headers['user-agent']
  });

  return { token };
}

// Middleware: Require admin authentication
function requireAdmin(req, res, next) {
  const token = req.cookies.admin_session;

  if (!token) {
    return res.redirect('/admin/login');
  }

  const tokenHash = crypto.createHash('sha256').update(token).digest('hex');

  db.adminSessions.findOne({ where: { tokenHash } })
    .then(session => {
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
    })
    .catch(err => {
      console.error('Session validation error:', err);
      res.redirect('/admin/login');
    });
}

// Protected admin routes
app.get('/admin', requireAdmin, (req, res) => {
  res.render('admin/dashboard', { admin: req.admin });
});
```

---

## Database Schema Example

### PostgreSQL

```sql
CREATE TABLE admin_sessions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  token_hash VARCHAR(64) NOT NULL UNIQUE,
  admin_id UUID NOT NULL,
  admin_email VARCHAR(255) NOT NULL,
  admin_name VARCHAR(255),
  expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
  ip_address VARCHAR(45),
  user_agent TEXT,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_admin_sessions_token_hash ON admin_sessions(token_hash);
CREATE INDEX idx_admin_sessions_admin_id ON admin_sessions(admin_id);
CREATE INDEX idx_admin_sessions_expires_at ON admin_sessions(expires_at);
```

### Prisma Schema

```prisma
model AdminSession {
  id          String   @id @default(uuid())
  tokenHash   String   @unique @map("token_hash")
  adminId     String   @map("admin_id")
  adminEmail  String   @map("admin_email")
  adminName   String?  @map("admin_name")
  expiresAt   DateTime @map("expires_at")
  ipAddress   String?  @map("ip_address")
  userAgent   String?  @map("user_agent")
  createdAt   DateTime @default(now()) @map("created_at")
  updatedAt   DateTime @updatedAt @map("updated_at")

  @@index([tokenHash])
  @@index([adminId])
  @@index([expiresAt])
  @@map("admin_sessions")
}
```

---

## Deployment Checklist

- [ ] Register your application in Account Server (get `client_id`)
- [ ] Configure `YOUR_APP_CLIENT_ID` environment variable
- [ ] Configure `ACCOUNT_SERVER_URL` for production
- [ ] Run database migrations (create `admin_sessions` table)
- [ ] Create admin accounts in Account Server with admin role
- [ ] Grant your application to admin accounts (via organization)
- [ ] Enable MFA for admin accounts (recommended)
- [ ] Test full login flow including MFA
- [ ] Set up session cleanup job (optional but recommended)
- [ ] Configure monitoring for failed login attempts

---

## Troubleshooting

### "Invalid credentials" but password is correct

- Verify admin account exists in Account Server
- Check if account has `admin` role
- Confirm account is active (email verified)

### "No permission" after successful login

- Verify `YOUR_APP_CLIENT_ID` is set correctly
- Confirm admin's organization owns the application
- Check that admin is a member of the organization

### MFA code always invalid

- Verify time synchronization on admin's device
- Check if MFA session token has expired (typically 5 minutes)
- Ensure correct TOTP app is being used

### Session expires immediately

- Check `expires_at` calculation uses correct timezone
- Verify database stores timestamps correctly
- Confirm cookie `maxAge` matches session TTL

---

## Support

- API Reference: See [API Reference](./api-reference.md)
- Authentication Details: See [Authentication](./authentication.md)
- Issues: Contact your organization administrator
