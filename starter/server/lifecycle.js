import {
  badRequest,
  forbidden,
  lastOwner,
} from './http.js';

export function roleRanks(db) {
  const rows = db.prepare(`
    SELECT key, rank
    FROM roles
  `).all();

  return Object.fromEntries(
    rows.map((row) => [row.key, row.rank])
  );
}

export function assertRoleExists(db, role) {
  const found = db.prepare(`
    SELECT key
    FROM roles
    WHERE key = ?
    LIMIT 1
  `).get(role);

  if (!found) {
    throw badRequest('unknown role');
  }

  return found;
}

export function assertCanModify(db, callerRole, targetRole) {
  const ranks = roleRanks(db);

  if (!(callerRole in ranks) || !(targetRole in ranks)) {
    throw forbidden('cannot modify this member');
  }

  // Owners may manage another owner, subject to LAST_OWNER protection.
  if (callerRole === 'owner' && targetRole === 'owner') {
    return;
  }

  if (ranks[callerRole] <= ranks[targetRole]) {
    throw forbidden('cannot modify member of equal or higher role');
  }
}

export function assertNotLastOwner(db, orgId, userId) {
  const membership = db.prepare(`
    SELECT role, status
    FROM memberships
    WHERE org_id = ?
      AND user_id = ?
    LIMIT 1
  `).get(orgId, userId);

  if (
    !membership ||
    membership.role !== 'owner' ||
    membership.status !== 'active'
  ) {
    return;
  }

  const row = db.prepare(`
    SELECT COUNT(*) AS n
    FROM memberships
    WHERE org_id = ?
      AND role = 'owner'
      AND status = 'active'
  `).get(orgId);

  if (row.n <= 1) {
    throw lastOwner();
  }
}

export function endActiveSessions(
  db,
  {
    orgId,
    userId = null,
    deviceId = null,
    reason,
    exceptSessionId = null,
  }
) {
  const where = [
    `org_id = ?`,
    `state = 'active'`,
  ];

  const args = [orgId];

  if (userId) {
    where.push(`user_id = ?`);
    args.push(userId);
  }

  if (deviceId) {
    where.push(`device_id = ?`);
    args.push(deviceId);
  }

  if (exceptSessionId) {
    where.push(`id <> ?`);
    args.push(exceptSessionId);
  }

  const now = new Date().toISOString();

  db.prepare(`
    UPDATE sessions
    SET
      state = 'ended',
      end_reason = ?,
      ended_at = ?
    WHERE ${where.join(' AND ')}
  `).run(reason, now, ...args);
}

export function snapshotAuthority(
  db,
  { userId, orgId, deviceId }
) {
  const membership = db.prepare(`
    SELECT role
    FROM memberships
    WHERE org_id = ?
      AND user_id = ?
      AND status = 'active'
    LIMIT 1
  `).get(orgId, userId);

  return {
    role: membership?.role ?? null,
    deviceId,
    snapshotAt: new Date().toISOString(),
  };
}

export function sessionExpiry(db, orgId) {
  const org = db.prepare(`
    SELECT max_session_minutes
    FROM organizations
    WHERE id = ?
      AND deleted_at IS NULL
    LIMIT 1
  `).get(orgId);

  if (!org) return null;

  return new Date(
    Date.now() + org.max_session_minutes * 60_000
  ).toISOString();
}