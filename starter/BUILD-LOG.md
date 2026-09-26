# BUILD-LOG

This log records the implementation, debugging, reversals, and hardening work completed while building RemoteOps.

---

## Phase 0 — orientation

I started by reading the README, DISCOVERY-BRIEF, permission model, schema, UI inventory, and starter code before implementing anything.

The starter already had the database structure, seed data, and test harnesses, but the main authentication verification, caller context, permission engine, API routes, audit logic, lifecycle behavior, and React console still needed implementation.

One important thing I noticed was that the project also generates a personalized role and permission, so the implementation could not depend only on the documented role/permission list.

I also noticed that some starter code assumed POSIX-style path and shell behavior, while I was developing on Windows. This later caused real failures in database loading and production frontend serving.

---

## Phase 1 — token verification

Implemented `verifyAccessToken` in `server/auth.js`.

The initial JWT test failed because token verification was still a stub.

I added checks for:

- exactly three JWT segments
- valid JSON header and payload
- object-shaped header and payload
- `alg === HS256`
- `typ === JWT`
- HMAC SHA-256 signature verification
- constant-time signature comparison
- numeric expiry
- issuer
- audience
- non-empty `jti`

One important boundary case was token expiry. The test suite treats `exp == now` as already expired, so the verifier follows half-open validity semantics.

After implementation:

```text
node scripts/check-jwt.js
43 passed, 0 failed
```

---

## Phase 2 — caller context and permission engine

Implemented `server/context.js` and `server/permissions.js`.

The caller context now:

- reads the Bearer token
- verifies the JWT
- loads the user's membership
- enforces organization isolation
- checks `perm_version`
- supplies the current organization and role to route handlers

Initially I thought role permissions alone would be enough, but the permission tests showed that grants can affect different devices differently.

I changed the permission model to dynamically combine:

- role baseline
- organization-wide grants
- device-scoped grants
- allow grants
- deny grants
- validity windows

The important precedence case was `org-wide deny + device-scoped allow`.

My first instinct was that the more specific device-level allow might win. The test suite showed that this was wrong.

The final rule became: **explicit deny wins regardless of scope** before role baseline or allow grants are considered.

I also avoided hardcoding the role/permission matrix because the personalization test adds an undocumented role and permission.

The engine now reads authorization data directly from SQLite at runtime.

After implementation:

```text
node scripts/check-permissions.js
35 passed, 0 failed

npm run personalisation
18 passed, 0 failed
```

The personalization run confirmed that the generated `reviewer` role and `device:reboot` permission work without adding either value to application constants.

---

## Phase 3 — Windows database path bug

While running the API checks on Windows, `scripts/load-db.js` failed before the application logic was reached.

The loader originally converted module-relative URLs using:

```js
new URL(...).pathname
```

On Windows this produced an invalid filesystem path.

I replaced it with `fileURLToPath(...)` from `node:url`.

The helper became:

```js
const here = (p) => fileURLToPath(new URL(p, import.meta.url));
```

After this change the database loader worked correctly.

This later helped identify the same type of issue in production static-file serving.

---

## Phase 4 — API implementation

Implemented the main API routes for:

- authentication
- organization switching
- organization creation
- members
- devices
- grants
- sessions
- invites
- audit

Important behaviors implemented and tested:

- role changes increase `perm_version`
- stale access tokens are rejected
- role/grant changes do not end existing sessions
- suspension and removal do end active sessions
- devices without `device:view` are completely hidden
- unknown permissions are rejected
- self-grants are rejected
- privilege laundering is blocked
- invite tokens are hashed and single-use
- cross-org resources return 404 instead of 403

A key session behavior was grandfathering.

I initially considered terminating existing sessions whenever permissions changed, but the API tests showed that this was incorrect.

Role or grant changes must affect future authorization without terminating an already-active session.

Suspension, membership removal, and device transfer are different because they are tenancy/account integrity events, so those do terminate sessions.

After completing the API:

```text
node scripts/check-api.js
66 passed, 0 failed
```

---

## Phase 5 — React console

The original frontend was only a starter placeholder.

Implemented the React console in `web/main.jsx`.

The console includes:

- login
- organization switching
- active role display
- organization-specific theme
- Devices
- People
- Grants
- Sessions
- Audit
- Admin
- organization creation
- invitation redemption
- login error feedback

The frontend does not contain a role-to-permission matrix.

All permission-based UI elements are rendered using permissions returned by the server.

The UI rule is:

```text
permission allowed
    -> element exists
    -> data-state="unlocked"

permission denied
    -> element is absent from the DOM
```

This is especially important for device rows because the same user can have different permissions on different devices.

The Playwright suite also checks this architecture by modifying the server response and confirming that the related UI control disappears.

---

## Phase 5.1 — refresh-token support

The UI test suite required a logged-in user to remain logged in after a page reload without storing the access token in browser storage.

Implemented:

- refresh token creation on login
- hashed refresh tokens in SQLite
- HttpOnly refresh cookie
- `SameSite=Strict`
- `Secure`
- refresh-token rotation
- `/v1/auth/refresh`

The access token remains only in React memory.

The UI tests confirm that localStorage and sessionStorage remain empty while the session can still be restored after a reload.

---

## Phase 5.2 — Playwright browser setup

The first Playwright run showed all 25 tests failing immediately.

The actual problem was not the application. Playwright reported that the Chromium executable was missing.

Installing Chromium fixed the environment issue:

```text
npx playwright install chromium
```

After that, the UI tests could run against the application.

---

## Phase 5.3 — production frontend path bug

After Chromium was installed, the UI tests still timed out waiting for elements such as `login-email` and `app-shell`.

Initially this looked like a React problem.

The actual cause was production static-file serving.

Playwright starts the server in production mode, and `server/index.js` was using:

```js
new URL('../dist/', import.meta.url).pathname
```

which caused the same Windows path issue seen earlier in the database loader.

I replaced it with:

```js
fileURLToPath(new URL('../dist/', import.meta.url))
```

After rebuilding, the frontend loaded correctly under the Playwright production server.

The complete UI suite then passed:

```text
25 passed
```

---

## Phase 6 — audit logging

Implemented `server/audit.js`.

Audit rows contain:

- organization
- actor
- action
- target
- allow/deny result
- reason code
- request ID
- timestamp

Successful state changes and their audit rows are written inside the same SQLite transaction.

This avoids a case where the mutation succeeds but the process fails before the audit row is written.

Denied permission attempts are recorded using `auditDenials(...)`.

The wrapper records the denial with the machine-readable reason and then rethrows the original error.

I also relied on a database guarantee instead of reimplementing it in application code.

The `audit_events` table already has SQLite triggers preventing UPDATE and DELETE, so the application only inserts audit events.

Audit logging was integrated into important state-changing operations including:

- grant creation/revocation
- session start/termination
- member lifecycle changes
- invite creation/revocation
- organization changes
- device mutations

---

## Phase 7 — endpoint completion

After the public tests passed, I compared the implemented routes with the full endpoint list in the brief.

Some documented endpoints were still missing even though the visible tests did not require all of them.

Added:

```text
PATCH  /v1/orgs/:org
DELETE /v1/orgs/:org

GET    /v1/orgs/:org/devices/:id
POST   /v1/orgs/:org/devices
PATCH  /v1/orgs/:org/devices/:id
DELETE /v1/orgs/:org/devices/:id

POST   /v1/orgs/:org/devices/:id/transfer

DELETE /v1/sessions/:id

GET    /v1/orgs/:org/users/:userId/effective
```

Device transfer requires the required authority in both the source and destination organizations.

Device transfer and decommissioning also terminate active sessions on the affected device.

---

## Phase 7.1 — session end reason bug

While implementing session termination, I initially used:

```text
user_ended
terminated_by_admin
```

The database schema rejected these values because `sessions.end_reason` has a strict CHECK constraint.

The schema-supported values are:

```text
user_stopped
admin_terminated
```

I changed the route implementation to use the database-supported values.

This was a case where the database constraint was the final source of truth.

---

## Phase 8 — authorization hardening

After the documented endpoint surface was complete, I reviewed hidden-test-sensitive behavior.

Confirmed or hardened:

- permissions are loaded dynamically from the database
- there is no hardcoded role matrix
- explicit deny always wins
- grant validity windows are half-open
- wildcard permissions work by resource family
- cross-org access does not leak resource existence
- last-owner protection works
- self role-change is blocked
- self-grants are blocked
- privilege laundering is blocked
- role/grant changes do not end active sessions
- suspension/removal/device transfer do end active sessions
- stale tokens are rejected through `perm_version`
- device permissions are resolved per device

---

## Phase 9 — performance decision

The device list could easily create an N+1 authorization query problem.

Instead of resolving the full permission state separately for every device, `resolveDevices(...)` loads the authorization state once and evaluates all device rows from that state.

This avoids repeatedly querying membership, role baseline, and grants for every device.

I chose not to add caching.

For the current architecture — single process, local SQLite, fresh authorization reads, and `perm_version` invalidation — fresh resolution is simpler and avoids the risk of stale authorization.

If the system became distributed later, I would consider a short-TTL cache keyed by:

```text
org_id:user_id:perm_version
```

---

## Phase 10 — cross-platform cleanup

The original package scripts used POSIX-style commands:

```text
NODE_ENV=production node server/index.js
rm -f app.db app.db-wal app.db-shm
```

These do not work the same way on Windows.

The database loader already deletes the database files itself before recreating them, so `db:reset` was simplified to run the loader directly.

Production startup was moved to a small Node script that sets:

```js
process.env.NODE_ENV = 'production';
```

before importing the server.

This makes the main npm commands work consistently across Windows, macOS, and Linux.

---

## Final verification

Ran the full verification suite:

```text
node scripts/check-jwt.js
node scripts/check-permissions.js
npm run personalisation
node scripts/check-api.js
npm run build
npx playwright test
git status
```

Final results:

```text
JWT verification        43 passed, 0 failed
Permission engine       35 passed, 0 failed
Personalisation         18 passed, 0 failed
API contract            66 passed, 0 failed
Production build        PASS
Playwright UI           25 passed
```

Git status also showed:

```text
On branch main
Your branch is up to date with 'origin/main'.

nothing to commit, working tree clean
```

---

## Open threads

### Permission caching

Permission resolution is intentionally not cached.

For the current local SQLite application, fresh evaluation is simple and prevents stale permission results.

A distributed version could add a short-TTL cache keyed by `org_id`, `user_id`, and `perm_version`.

### Device transfer

Device transfer currently assumes both organizations exist in the same database.

A multi-region system would likely need a separate transfer workflow or signed transfer credential.

### Real remote access

The project intentionally does not implement:

- screen streaming
- keyboard/mouse injection
- remote shell execution
- real file transfer infrastructure

The project focuses on authorization, tenancy, session lifecycle, and audit behavior.

### Production security

The local fallback JWT secret exists only to make local development simple.

A real production deployment should require secrets from external configuration instead of relying on a fallback value.

### Rate limiting and account recovery

Rate limiting, password reset, and email delivery are not implemented because they are outside the assignment scope.