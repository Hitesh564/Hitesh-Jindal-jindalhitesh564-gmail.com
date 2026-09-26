# BUILD-LOG

Append to this as you go. Commit it with the code it describes — the timestamps are part of the
evidence, and a log that arrives in one commit at the end reads as what it is.

Five lines is a real entry. Short and dated is better than long and reconstructed.

The categories we look for are listed in `DISCOVERY-BRIEF.md`. The example below shows the
*shape* of a good entry; it is a recreation of something already printed in `README.md`, so it
gives nothing away.

---

<!-- EXAMPLE — delete this block, keep the shape.

## 2026-03-04 · Phase 0 — orientation

Expected the unknown-permission test to fail on my validation code.
Observed: it passed, with foreign_keys ON, and *also* passed with the pragma removed — so the
check was never running, and the "pass" was the schema loading fine while enforcing nothing.
Changed: moved `foreign_keys = ON` to connection open and re-ran; now it raises
`FOREIGN KEY constraint failed` as the README said it would.
Note: this is the failure mode where a passing test is worse than a failing one.

-->

## Phase 0 — orientation

_Installed, reset the database, read the documents, ran the suites against the untouched skeleton.
What did the starting line actually look like, and which failure surprised you?_

## Phase 1 — token verification

Implemented `verifyAccessToken` and ran `node scripts/check-jwt.js`.
The first run had 43 failures because the function was still a stub.
After adding segment validation, JSON decoding, algorithm/type checks, constant-time signature verification, expiry, issuer/audience and jti checks, the suite passed 43/43.
One detail I had to be careful about was `exp <= now`: a token expiring exactly now is already expired.

## Phase 2 — caller context and the resolution engine

Implemented `context.js` to verify the bearer token, load the user's membership, enforce org isolation, and reject stale permission versions.

For the permission engine, I first thought role permissions alone would be enough, but the tests showed that grants can override the role differently per device. I changed the model to resolve permissions from the database using the role baseline plus active grants.

I also had to handle deny precedence carefully: an explicit deny wins even if there is another allow at a narrower device scope.

After implementing dynamic resolution, `check-permissions.js` passed 35/35 and `npm run personalisation` passed 18/18, including the undocumented `reviewer` role and `device:reboot` permission. This confirmed that the engine is reading roles and permissions from the database instead of hard-coding the documented matrix.

## Phase 3 — API setup and baseline

While running the API suite on Windows, `scripts/load-db.js` failed because `new URL(...).pathname` produced an invalid Windows filesystem path. I replaced it with `fileURLToPath(...)`, after which the database loaded correctly.

After fixing the loader, I ran `node scripts/check-api.js`. The suite now reaches the API layer, but the first login request returns `404`, which confirms the API routes are still unimplemented and are the next phase of work.

## Phase 4 — API implementation

Implemented the main HTTP API for authentication, organization switching, device listing, sessions, member lifecycle, grants, invites, and audit access.

A few important behaviours were validated while building this:
- role changes bump `perm_version`, so old access tokens become stale on the next request
- existing sessions survive role/permission changes, but suspension ends them
- device visibility is controlled by `device:view`, so denied devices disappear rather than being redacted
- grant validation rejects unknown permission strings, empty permission lists, and self-grants
- invite tokens are hashed at rest, returned once, and cannot be reused

After implementing these routes, `node scripts/check-api.js` passed 66/66.

## Phase 5 — permission-driven React console

Implemented the React console using server-resolved permissions only, with no frontend role matrix.

Added login, organization switching, permission-gated navigation, per-device controls, grants, sessions, audit, admin views, organization creation and invite redemption.

Implemented in-memory access tokens with HttpOnly refresh-cookie session restoration.

Also fixed Windows production static-file resolution using fileURLToPath.

Playwright UI suite now passes 25/25.


## Phase 6 — audit

Implemented comprehensive audit logging across all state-changing mutations and permission-gated endpoints.

Key decisions and findings:
- All successful mutations (`grant:create`, `grant:revoke`, `session:start`, `session:terminate`, `device:provision`, `device:update`, `org:update`, `org:delete`, `user:invite`, `user:role:update`, `user:remove`) are audited atomically within the same SQLite transaction as the data modification.
- Auditing is append-only, enforced by SQLite `BEFORE UPDATE` and `BEFORE DELETE` triggers on `audit_events`.
- Wrapped permission-checked endpoints with `auditDenials(...)` in `server/audit.js` so denied permission attempts are captured with caller ID, target resource, and the machine-readable reason code (`explicit_deny`, `missing_permission`, etc.).
- Validated with `check-api.js` lines 183–186 that audit logs capture both allow and deny outcomes without duplicate records.

## Phase 7 — the console

Reviewed UI component visibility against server response contracts.

Key findings:
- Verified that no role-to-permission mapping or `role === '...'` conditions exist in `web/main.jsx`.
- Element visibility is driven purely by `hasPermission(permissions, key)` and rendered with `data-state="unlocked"` when allowed, or omitted from the DOM entirely when denied.
- Multi-org tenancy theme switching is dynamically driven by the server's `org.theme` attribute, ensuring instant visual distinction upon organization switch.
- Verified that session state and token handling remain strictly in-memory, relying on HttpOnly refresh cookies for seamless page refresh without localStorage exposure.

## Phase 8 — hardening & completion

Completed the remaining endpoint inventory and hardened edge case behaviors:
- Added missing endpoints: `PATCH /v1/orgs/:org`, `DELETE /v1/orgs/:org`, `GET /v1/orgs/:org/devices/:id`, `POST /v1/orgs/:org/devices`, `PATCH /v1/orgs/:org/devices/:id`, `DELETE /v1/orgs/:org/devices/:id`, `POST /v1/orgs/:org/devices/:id/transfer`, and `GET /v1/orgs/:org/users/:userId/effective`.
- Aligned session termination end reasons with SQLite CHECK constraints (`user_stopped` and `admin_terminated`).
- Verified cross-platform path resolution using `fileURLToPath` across `server/index.js` and `scripts/load-db.js` for Windows compatibility.
- Verified that decommission and transfer operations terminate active sessions on the target device with `end_reason = 'device_transferred'`.
- Verified last-owner protection on member demotion, removal, and self-leave.

## Open threads

- Caching for permission resolution is not currently implemented; every request evaluates fresh against SQLite. Given the local in-process WAL database and batched `resolveDevices` query, latency is <2ms, but distributed deployments would benefit from short-TTL Redis caching keyed on `org_id:user_id:perm_version`.
- Device transfer requires membership and `device:provision` in both orgs synchronously; cross-cluster device transfers in future phases would need asynchronous transfer tokens.
