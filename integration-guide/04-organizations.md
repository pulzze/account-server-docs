# Organizations

Organizations are named containers that group applications and users. All endpoints require `Authorization: Bearer <admin_jwt>`.

---

## List Organizations

```
GET /api/v1/admin/orgs
```

Returns organizations the authenticated admin belongs to.

Response:
```json
{
  "organizations": [
    {
      "id": "org_uuid",
      "name": "acme-corp",
      "display_name": "Acme Corporation",
      "status": "active",
      "role": "owner",
      "created_at": "2026-01-15T10:30:00Z"
    }
  ]
}
```

## Create Organization

```
POST /api/v1/admin/orgs
```

Request:
```json
{
  "name": "acme-corp",
  "display_name": "Acme Corporation"
}
```

**Name requirements:** 3-50 characters, lowercase letters, numbers, hyphens. Must start with a letter. Globally unique.

Response (201):
```json
{
  "name": "acme-corp",
  "display_name": "Acme Corporation",
  "status": "active",
  "created_at": "2026-01-15T10:30:00Z"
}
```

The creating admin becomes the owner.

## Get Organization

```
GET /api/v1/admin/orgs/:org_name
```

Auth: Admin JWT + org membership required.

Response:
```json
{
  "name": "acme-corp",
  "display_name": "Acme Corporation",
  "status": "active",
  "metadata": {},
  "created_at": "2026-01-15T10:30:00Z",
  "your_role": "owner",
  "member_count": 3
}
```

## Update Organization

```
PATCH /api/v1/admin/orgs/:org_name
```

Auth: Admin JWT + org membership required.

Only these fields can be updated:

| Field | Description |
|-------|-------------|
| `display_name` | Human-readable organization name |
| `metadata` | Arbitrary JSON metadata |

The organization `name` (slug) cannot be changed after creation.

## Delete Organization

```
DELETE /api/v1/admin/orgs/:org_name
```

Auth: Admin JWT + **owner** role required. Returns 204 No Content.

---

## Members

### List Members

```
GET /api/v1/admin/orgs/:org_name/members
```

Auth: Admin JWT + org membership required.

Response:
```json
{
  "members": [
    {
      "admin_id": "adm_abc123",
      "email": "admin@acme.com",
      "role": "owner",
      "joined_at": "2026-01-15T10:30:00Z"
    },
    {
      "admin_id": "adm_def456",
      "email": "dev@acme.com",
      "role": "member",
      "joined_at": "2026-01-20T14:00:00Z"
    }
  ]
}
```

### Remove Member

```
DELETE /api/v1/admin/orgs/:org_name/members/:admin_id
```

Auth: Admin JWT + org membership required.

Returns 204 No Content.

| Error | Status | Description |
|-------|--------|-------------|
| `Administrator not found` | 404 | No admin with that ID |
| `Member not found` | 404 | Admin is not a member of this org |
| `Cannot remove the last owner` | 400 | Every org must have at least one owner |

---

## Invitations

Invite other administrators to join your organization.

### List Invitations

```
GET /api/v1/admin/orgs/:org_name/invitations
```

Auth: Admin JWT + org membership required.

Response:
```json
{
  "invitations": [
    {
      "id": "inv_uuid",
      "email": "newdev@acme.com",
      "role": "member",
      "invited_by": "admin@acme.com",
      "expires_at": "2026-01-22T10:30:00Z",
      "created_at": "2026-01-15T10:30:00Z"
    }
  ]
}
```

### Create Invitation

```
POST /api/v1/admin/orgs/:org_name/invitations
```

Request:
```json
{
  "email": "newdev@acme.com",
  "role": "member"
}
```

| Field | Required | Default | Description |
|-------|----------|---------|-------------|
| `email` | Yes | — | Email of the administrator to invite |
| `role` | No | `"member"` | Role to assign: `"owner"` or `"member"` |

Response (201):
```json
{
  "id": "inv_uuid",
  "email": "newdev@acme.com",
  "role": "member",
  "expires_at": "2026-01-22T10:30:00Z"
}
```

> **Note:** `invitation_token` is included in development mode for testing.

| Error | Status | Description |
|-------|--------|-------------|
| `This person is already a member` | 400 | The email belongs to an existing member |

### Cancel Invitation

```
DELETE /api/v1/admin/orgs/:org_name/invitations/:id
```

Returns 204 No Content.

### Accept Invitation

```
POST /api/v1/admin/invitations/:token/accept
```

Auth: Admin JWT (the accepting administrator must be logged in).

Response:
```json
{
  "message": "Successfully joined the organization",
  "organization": "acme-corp",
  "role": "member"
}
```

| Error | Status | Description |
|-------|--------|-------------|
| `Invitation not found` | 404 | Invalid token |
| `This invitation was sent to a different email address` | 403 | Token email doesn't match logged-in admin |
| `Invitation has expired or already been used` | 400 | Expired or consumed |

---

## Roles and Permissions

Organizations have two roles:

| Role | Can Do |
|------|--------|
| **Owner** | Full access to all org resources. Can delete org, manage all apps and members. |
| **Member** | Access controlled by per-application permissions. |

### Application Permissions (Members)

Members have per-application permissions:

| Permission | Grants |
|------------|--------|
| `read` | View application details |
| `write` | Update application settings, change passwords, logout users |
| `delete` | Delete the application |

Owners have implicit full access to all applications.

---

## Endpoint Summary

| Action | Method | Endpoint | Auth |
|--------|--------|----------|------|
| List Orgs | GET | `/api/v1/admin/orgs` | Admin JWT |
| Create Org | POST | `/api/v1/admin/orgs` | Admin JWT |
| Get Org | GET | `/api/v1/admin/orgs/:org_name` | Admin JWT + member |
| Update Org | PATCH | `/api/v1/admin/orgs/:org_name` | Admin JWT + member |
| Delete Org | DELETE | `/api/v1/admin/orgs/:org_name` | Admin JWT + owner |
| List Members | GET | `/api/v1/admin/orgs/:org_name/members` | Admin JWT + member |
| Remove Member | DELETE | `/api/v1/admin/orgs/:org_name/members/:admin_id` | Admin JWT + member |
| List Invitations | GET | `/api/v1/admin/orgs/:org_name/invitations` | Admin JWT + member |
| Create Invitation | POST | `/api/v1/admin/orgs/:org_name/invitations` | Admin JWT + member |
| Cancel Invitation | DELETE | `/api/v1/admin/orgs/:org_name/invitations/:id` | Admin JWT + member |
| Accept Invitation | POST | `/api/v1/admin/invitations/:token/accept` | Admin JWT |
