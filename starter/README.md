# RemoteOps

RemoteOps is a multi-organization permission console for managing organizations, users, devices, grants, sessions, invitations, and audit activity.

The application runs as a single Node.js process:
- `/v1/*` serves the REST API
- the same server hosts the React/Vite frontend
- SQLite stores organizations, memberships, devices, grants, sessions, refresh tokens, invitations, and audit events

The authorization model is fully server-driven. Roles, permissions, role baselines, and grants are loaded dynamically from the database at runtime rather than hardcoded in the frontend.

---

## Features

### Authentication
- Email/password login
- HS256 JWT access tokens
- Access tokens kept only in memory in the browser
- HttpOnly refresh-token cookie
- Refresh-token rotation
- Organization-scoped access tokens
- Permission-version checks to invalidate stale tokens

### Multi-organization support
- A user can belong to multiple organizations
- The same user can have a different role in each organization
- Cross-organization resources are structurally isolated
- Unauthorized cross-org access returns `404 NOT_FOUND`

### Permission engine
- Runtime role and permission catalogue loaded from SQLite
- Role baseline permissions
- Organization-wide grants
- Device-scoped grants
- Explicit deny always wins
- Wildcard patterns such as `device:*`
- Half-open grant validity windows
- No self-grants
- No privilege laundering

### Devices
- List visible devices
- View individual devices
- Provision devices
- Update devices
- Decommission devices
- Transfer devices between organizations
- Per-device resolved permissions returned to the UI

### Membership lifecycle
- View members
- Change roles
- Suspend and reinstate members
- Remove members
- Leave an organization
- Last-owner protection
- Permission-version invalidation

### Sessions
- View, control, and terminal session modes
- Session permission checks are compound:
  - `session:start`
  - mode-specific device permission
- Control and terminal sessions are exclusive
- View sessions may coexist
- Existing sessions survive ordinary permission changes
- Suspension, membership removal, and device transfer terminate affected sessions
- Session expiry is bounded by organization TTL

### Grants
- Create allow/deny grants
- Organization-wide or device-scoped grants
- Runtime validation against the permission catalogue
- Grant provenance included in resolution
- Grant revocation invalidates future authorization without killing existing sessions

### Invitations
- Create invitations
- Single-use invite tokens
- Invite tokens are hashed at rest
- Public invite preview exposes only the minimum required data
- New users can accept invitations and create credentials
- Existing users can join additional organizations

### Audit
- Append-only audit events
- Successful mutations are logged atomically with the database change
- Denied permission attempts are also logged
- SQLite triggers prevent audit updates/deletes
- Pagination is supported

### Frontend
- React single-page application
- Permission-driven navigation
- Permission-gated controls are present or absent, never disabled
- No frontend role-to-permission matrix
- Organization-specific visual theme
- Organization switching
- Grant creation
- Invite redemption
- Session restoration through the refresh cookie

---

## Requirements

- Node.js 22+
- npm

Playwright requires Chromium once:

```sh
npx playwright install chromium