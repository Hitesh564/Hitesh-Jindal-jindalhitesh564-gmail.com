# DECISIONS

One section per decision that a reviewer might reasonably have made differently. Every section has
the same four parts, and the third and fourth are the ones we weigh most.

---

### 1. Deny precedence evaluated before role baseline and grant allowances across scopes

**What I chose:** Evaluate any applicable explicit `deny` grant at the relevant scope first; if present, return `{ effect: 'deny', source: 'grant:...', reason: 'explicit_deny' }` immediately before checking role baselines or allow grants.

**Why:** In `check-permissions.js` line 44 (`the discriminating case: org-wide deny + device-scoped allow`), having an org-wide grant of `deny device:terminal` must override a device-specific grant of `allow device:terminal` on `dev_lab_win_01`. When I evaluated allow rules before checking global denies, the device-scoped allow mistakenly won. Enforcing D1 in `server/permissions.js:resolveExact` lines 180–195 fixed this.

**What I rejected:** Specificity-based resolution (where narrower scope device grants override broader org grants) and timestamp-based last-write-wins resolution. Both fail because an organization-wide restriction is an explicit safety barrier that must not be punctured by an ad-hoc local grant.

**What would change my mind:** A multi-tenant requirement where organizations explicitly support exception/carve-out grants with higher administrative priority tokens.

---

### 2. Catalogue-driven runtime permission resolution instead of hardcoded matrices

**What I chose:** Read the dynamic permission catalogue from the SQLite `permissions` and `role_permissions` tables on every request in `server/permissions.js:loadState`.

**Why:** Running `npm run personalisation` generated a runtime overlay with an undocumented role (`reviewer`) and undocumented permission (`device:reboot`). When resolution was tested against `check-personalisation.js`, a static 5-role/19-permission matrix failed to recognize `reviewer` or `device:reboot`. Dynamically loading rows from SQLite allows any custom role or permission in `app.db` to resolve correctly.

**What I rejected:** Hardcoding the standard 5-role / 19-permission matrix in JavaScript constants or TypeScript unions.

**What would change my mind:** A strict requirement for zero-query memory-only permission evaluation in high-throughput environments where DB schema changes trigger service redeployments.

---

### 3. Batched single-query state resolution for device lists

**What I chose:** Load the user's membership, role baseline, and active grants in a single database read in `resolveDevices` (`server/permissions.js:408`), then evaluate permissions in memory for all device rows.

**Why:** In `server/routes/devices.js:listDevices`, calling individual resolution queries per device caused an N+1 query pattern (1 query for devices + 3 queries per device for state/baseline/grants). For 50 devices, this generated over 150 SQL queries. `resolveDevices` collapsed this to 1 list query + 1 state query.

**What I rejected:** Resolving permissions by looping and calling `resolve(db, ...)` inside each iteration of the device list.

**What would change my mind:** If device rows required distinct federated authorization providers or external attribute lookups that could not be batched.

---

### 4. Cross-org resource requests return 404 NOT_FOUND rather than 403 FORBIDDEN

**What I chose:** In `server/context.js:48`, compare the URL's `:org` parameter against `claims.org` in the verified JWT; if they mismatch, immediately throw `notFound()` (`404 NOT_FOUND`).

**Why:** `check-api.js:72-74` verifies that an Acme token querying Globex endpoints returns HTTP 404 with error code `NOT_FOUND` and leaks no metadata. Returning 403 would reveal to an attacker that the targeted org or resource ID exists, creating an enumeration oracle.

**What I rejected:** Returning `403 FORBIDDEN` or performing a database lookup to check if the caller is a member before returning 404.

**What would change my mind:** An internal debugging mode or administrative API where audit compliance requires distinguishing unauthorized access attempts from genuinely missing endpoints.

---

### 5. Grandfathering active sessions on permission changes with TTL enforcement

**What I chose:** Session authority is snapshotted into `authorized_by` at creation time (`server/routes/sessions.js:129`) and live sessions survive role demotions or grant revocations. Grandfathering is bounded by `org.max_session_minutes` (`expires_at`).

**Why:** `check-api.js:123-127` tests that when owner demotes Sam to viewer, her active control session remains active and `end_reason` remains null. However, account-level events (suspension via `POST /members/:id/suspend` and membership removal) explicitly terminate active sessions via `endActiveSessions()` (`server/lifecycle.js:80`).

**What I rejected:** Terminating sessions immediately upon every grant revocation or role modification, or allowing sessions to run indefinitely without an expiry TTL.

**What would change my mind:** A zero-trust security policy requiring instant revocation of live device control sessions whenever any permission is modified.

---

### 6. Atomic database-bound audit logging for state mutations

**What I chose:** Execute state changes and their corresponding `audit()` writes within the exact same SQLite transaction (`db.transaction(...)`), while wrapping permission-gated route handlers with `auditDenials(...)` (`server/audit.js:48`).

**Why:** In `server/routes/grants.js:213-281`, `server/routes/sessions.js:140-185`, and `server/routes/orgs.js`, mutating database state without committing the audit event in the same transaction leads to inconsistent audit logs if the process crashes or an insert constraint fails. `check-api.js:183-186` requires audit logs to contain denied attempts with exact reason codes.

**What I rejected:** Asynchronous out-of-band audit event publishing or writing audit logs after HTTP response completion.

**What would change my mind:** High-concurrency distributed write workloads where append-only audit event streams must be offloaded to Apache Kafka or AWS Kinesis to prevent database lock contention.

---

### 7. Dual bearer credential domains for refresh and invite tokens

**What I chose:** Separate HMAC hashing domains for refresh tokens (`${APP_HASH_KEY}:refresh`) and invite tokens (`${APP_HASH_KEY}:invite`) using Node's `crypto.createHmac` in `server/auth.js:204-209`.

**Why:** `AUTH-DATA-MODEL.md §6` and `db/schema.sql:110,223` dictate that raw tokens must never be stored in plaintext. If both token types shared a single raw SHA-256 hash, a hash collision or leaked hash from one table could be cross-correlated or replayed against another table.

**What I rejected:** Storing raw tokens in SQLite or using generic unkeyed SHA-256 hashes without domain separation.

**What would change my mind:** Migration to an external identity provider (such as Auth0 or AWS Cognito) where token lifecycle and credential hashing are managed outside the application.

---

### 8. Strict half-open intervals for token and grant expirations

**What I chose:** Enforce half-open time comparisons (`starts_at <= now < expires_at`), treating `exp <= now` or `expires_at <= now` as expired.

**Why:** In `server/auth.js:150` and `check-jwt.js:146` (`exp exactly now`), a token whose expiration timestamp is equal to the current second is already expired. Furthermore, in `server/http.js:normalizeTs`, all client timestamps are parsed and converted to canonical ISO-8601 UTC with 'Z' so lexicographical string comparisons in SQLite queries match chronological ordering.

**What I rejected:** Closed interval comparisons (`now <= expires_at`) and accepting non-canonical timezone offsets (`+00:00`), which sort before `Z` in SQLite text comparisons.

**What would change my mind:** An external API standard explicitly requiring closed-interval validity periods.

---

## Where this repo argues with itself

1. **Session Termination End Reasons in Schema vs Code:**
   - **Schema Contract:** `db/schema.sql` lines 170–172 enforce `CHECK (end_reason IN ('user_stopped','user_suspended','membership_removed','device_transferred','admin_terminated','session_expired','superseded'))`.
   - **Initial Route Code:** In `server/routes/sessions.js:terminateSession`, the handler initially assigned `'user_ended'` and `'terminated_by_admin'`.
   - **Choice & Rationale:** I aligned the route handler with the schema's STRICT `CHECK` constraints (`'user_stopped'` and `'admin_terminated'`). The schema is the definitive arbiter of validity in this repo.

2. **Cross-Org Device Access — Visibility vs Authorization:**
   - **Document Statement:** `BRIEF.md §5.1` states `POST /devices/:id/transfer` requires `device:provision` in both orgs, while `PERMISSIONS.md §5` states that resources in another org must return `404 NOT_FOUND` to prevent information leaks.
   - **Choice & Rationale:** In `server/routes/devices.js:transferDevice`, the source device must exist in the caller's active org (otherwise `404`). The target org ID is accepted in the request body, and we verify the caller holds `device:provision` in that target org via their active membership before transferring.

---

## Deliberately not built

1. **Real Remote Access (Screen streaming, input injection, shell execution):**
   - *Reason:* Explicitly forbidden by `BRIEF.md §4`. Sessions are control-plane audit and lifecycle records, not media streams.

2. **Email Delivery Provider:**
   - *Reason:* Invite tokens are single-use credentials returned directly in the `POST /v1/orgs/:org/invites` response for the console to display and copy (`README.md §Deliberately not here`).

3. **Client-Side Role-to-Permission Matrix:**
   - *Reason:* `PERMISSIONS.md §8` and `README.md §Two rules that shape the whole design` forbid hardcoded client matrices. The UI derives all button/card visibility strictly from server-resolved `permissions` and `data-state="unlocked"`.
