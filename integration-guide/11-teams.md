# Teams

Teams are subgroups of users within an Organization. They give end-user apps a way to scope content and context to a subset of an organization's users without spinning up a separate Organization for every group.

A user can belong to multiple Teams within their Organization. Cross-organization memberships are not allowed.

```
Organization (B2)              "acme-corp"
    └── Team (B3)              "engineering"
            └── TeamMembership (joins User → Team with a role)
```

Admin endpoints (`/api/v1/admin/orgs/:org_name/teams/...`) require `Authorization: Bearer <admin_jwt>` and the admin must be a member of the organization. The user-self endpoint (`/api/v1/users/me/teams`) requires `Authorization: Bearer <user_jwt>`.

---

## List Teams

```
GET /api/v1/admin/orgs/:org_name/teams
```

Returns active teams in the organization. Use `?status=archived` for archived teams only, `?status=all` for both.

Response:
```json
{
  "teams": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "organization_id": "org_uuid",
      "name": "engineering",
      "display_name": "Engineering",
      "description": "Product engineering team",
      "status": "active",
      "metadata": {},
      "created_at": "2026-05-16T10:30:00Z",
      "updated_at": "2026-05-16T10:30:00Z"
    }
  ]
}
```

## Create Team

```
POST /api/v1/admin/orgs/:org_name/teams
```

Request:
```json
{
  "name": "engineering",
  "display_name": "Engineering",
  "description": "Product engineering team"
}
```

**Name requirements:** 1–100 characters, lowercase letters, numbers, hyphens. Cannot start or end with a hyphen. Unique within the organization.

Response (201): same shape as the list response above.

| Error | Status | Description |
|-------|--------|-------------|
| Validation errors (name format, duplicate, etc.) | 422 | See `error.details` |

## Get Team

```
GET /api/v1/admin/orgs/:org_name/teams/:team_id
```

Returns the team if it belongs to the named organization.

| Error | Status | Description |
|-------|--------|-------------|
| Team not found in this org | 404 | Either the team doesn't exist or it belongs to a different org (no leak) |

## Update Team

```
PATCH /api/v1/admin/orgs/:org_name/teams/:team_id
```

Updates `display_name`, `description`, or `metadata`. The team `name` is immutable.

Request:
```json
{
  "display_name": "Platform Engineering",
  "description": "Updated description"
}
```

## Archive Team

```
DELETE /api/v1/admin/orgs/:org_name/teams/:team_id
```

Archives the team (`status: "archived"`). The row is preserved — this is a soft delete. Memberships persist but the team is excluded from default listings.

Response: the archived team JSON.

To restore an archived team, call `PATCH` with `{"status": "active"}` is **not** supported in v1 — use the API directly via the underlying `Teams.activate_team/1` context function from a maintenance script, or contact your admin.

---

## Team Memberships

### List Members

```
GET /api/v1/admin/orgs/:org_name/teams/:team_id/members
```

Returns memberships in `joined_at` order, with user info preloaded. Use `?role=author` or `?role=member` to filter.

Response:
```json
{
  "members": [
    {
      "user_id": "usr_def456",
      "username": "alice",
      "email": "alice@acme.com",
      "role": "author",
      "joined_at": "2026-05-16T10:35:00Z"
    }
  ]
}
```

### Add Member

```
POST /api/v1/admin/orgs/:org_name/teams/:team_id/members
```

Request:
```json
{
  "user_id": "usr_def456",
  "role": "member"
}
```

`role` defaults to `"member"` if omitted. Valid roles: `member`, `author`.

Response (201):
```json
{
  "user_id": "usr_def456",
  "username": "alice",
  "email": "alice@acme.com",
  "role": "member",
  "joined_at": "2026-05-16T10:35:00Z"
}
```

| Error | Status | Description |
|-------|--------|-------------|
| `user does not belong to this organization` | 422 | The `user_id` references a user in another org |
| `user_id is required` | 422 | Missing `user_id` in body |
| `user is already a member of this team` | 422 | Duplicate membership |
| Unknown role | 422 | `role` not in `member`/`author` |

### Update Member Role

```
PATCH /api/v1/admin/orgs/:org_name/teams/:team_id/members/:user_id
```

Request:
```json
{
  "role": "author"
}
```

Returns the updated membership JSON. `:user_id` is the user's `usr_xxx` short ID.

### Remove Member

```
DELETE /api/v1/admin/orgs/:org_name/teams/:team_id/members/:user_id
```

Returns 204 No Content.

| Error | Status | Description |
|-------|--------|-------------|
| Membership not found | 404 | User isn't a member, or team/user isn't in this org |

---

## User-Self: My Teams

```
GET /api/v1/users/me/teams
```

Auth: User JWT. Returns the authenticated user's active team memberships with their role per team. Use `?status=all` to include archived teams.

Response:
```json
{
  "teams": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "organization_id": "org_uuid",
      "name": "engineering",
      "display_name": "Engineering",
      "status": "active",
      "role": "author"
    }
  ]
}
```

Use this endpoint to populate a team-context selector in your application's UI. Pair it with the [`X-Active-Team-Id` flow](09-service-api.md#active-team-context-validation) when calling backend services.

---

## Active Team Context

Teams enable per-request context selection — e.g., "I am currently working as a member of the engineering team." The pattern:

1. Your app calls `GET /api/v1/users/me/teams` to populate a selector for the signed-in user.
2. The user picks a team.
3. Your app sets `X-Active-Team-Id: <team_id>` on subsequent requests to your backend services.
4. Your backend services validate the header against Account Server's [Service API](09-service-api.md#active-team-context-validation) using `POST /internal/validate?include=teams`.

The active team is **not** baked into the user's JWT — the user can change context mid-session without re-issuing tokens.

---

## Endpoint Summary

| Action | Method | Endpoint | Auth |
|--------|--------|----------|------|
| List Teams | GET | `/api/v1/admin/orgs/:org_name/teams` | Admin JWT + member |
| Create Team | POST | `/api/v1/admin/orgs/:org_name/teams` | Admin JWT + member |
| Get Team | GET | `/api/v1/admin/orgs/:org_name/teams/:team_id` | Admin JWT + member |
| Update Team | PATCH | `/api/v1/admin/orgs/:org_name/teams/:team_id` | Admin JWT + member |
| Archive Team | DELETE | `/api/v1/admin/orgs/:org_name/teams/:team_id` | Admin JWT + member |
| List Members | GET | `/api/v1/admin/orgs/:org_name/teams/:team_id/members` | Admin JWT + member |
| Add Member | POST | `/api/v1/admin/orgs/:org_name/teams/:team_id/members` | Admin JWT + member |
| Update Member Role | PATCH | `/api/v1/admin/orgs/:org_name/teams/:team_id/members/:user_id` | Admin JWT + member |
| Remove Member | DELETE | `/api/v1/admin/orgs/:org_name/teams/:team_id/members/:user_id` | Admin JWT + member |
| My Teams | GET | `/api/v1/users/me/teams` | User JWT |
