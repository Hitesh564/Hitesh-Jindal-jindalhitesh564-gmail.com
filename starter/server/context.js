// Per-request context: turn a bearer token into an authenticated caller.

import { verifyAccessToken, assertFresh } from './auth.js';
import { unauthenticated, notFound } from './http.js';

export function authenticate(db, secret) {
  return function buildContext(req, params) {
    // 1. Read Authorization header
    const authHeader = req.headers.authorization;

    if (
      typeof authHeader !== 'string' ||
      !authHeader.startsWith('Bearer ')
    ) {
      throw unauthenticated('missing bearer token');
    }

    // 2. Extract raw token
    const token = authHeader.slice('Bearer '.length).trim();

    if (!token) {
      throw unauthenticated('missing bearer token');
    }

    // 3. Verify JWT
    const claims = verifyAccessToken(token, secret);

    // Basic required claims
    if (
      typeof claims.sub !== 'string' ||
      !claims.sub ||
      typeof claims.org !== 'string' ||
      !claims.org
    ) {
      throw unauthenticated('invalid access token');
    }

    const userId = claims.sub;
    const orgId = claims.org;

    // 4. Structural org isolation
    // If the route contains an org parameter, it must match the token's org.
    //
    // Different route definitions may call it `org` or `orgId`,
    // so support both.
    const requestedOrg = params?.org ?? params?.orgId ?? null;

    if (requestedOrg && requestedOrg !== orgId) {
      throw notFound();
    }

    // 5. Find active membership for this user in this org
    const membership = db.prepare(`
      SELECT
        id,
        org_id,
        user_id,
        role,
        status,
        perm_version,
        invited_by,
        joined_at,
        created_at
      FROM memberships
      WHERE org_id = ?
        AND user_id = ?
      LIMIT 1
    `).get(orgId, userId);

    if (!membership) {
      throw unauthenticated('not a member of this org');
    }

    // Suspended / invited / removed users are not active callers.
    if (membership.status !== 'active') {
      throw unauthenticated('membership is not active');
    }

    // 6. Ensure organization itself still exists
    const org = db.prepare(`
      SELECT id, name, theme, max_session_minutes, deleted_at
      FROM organizations
      WHERE id = ?
        AND deleted_at IS NULL
      LIMIT 1
    `).get(orgId);

    if (!org) {
      throw unauthenticated('organization is unavailable');
    }

    // 7. Token must still reflect current authorization state
    assertFresh(claims, membership);

    // 8. Optional consistency check:
    // role in the signed token should agree with current membership.
    //
    // Usually perm_version should already invalidate a changed role,
    // but this keeps the caller internally consistent.
    if (claims.role !== membership.role) {
      throw unauthenticated('token role is stale');
    }

    // 9. Return authenticated caller context
    return {
      userId,
      orgId,
      role: membership.role,
      membership,
      claims,
      org,
    };
  };
}