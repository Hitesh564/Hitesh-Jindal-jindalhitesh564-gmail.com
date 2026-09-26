import {
  send,
  notFound,
  forbidden,
  selfRoleChange,
  badRequest,
} from '../http.js';

import {
  newId,
  bumpPermVersion,
} from '../db.js';

import {
  assertCan,
} from '../permissions.js';

import {
  assertRoleExists,
  assertCanModify,
  assertNotLastOwner,
  endActiveSessions,
  roleRanks,
} from '../lifecycle.js';


// -----------------------------------------------------------------------------
// GET /v1/orgs
// -----------------------------------------------------------------------------

function listOrgs({ db }) {
  return async function handler(ctx, params, res) {
    const orgs = db.prepare(`
      SELECT
        o.id,
        o.name,
        o.theme,
        m.role
      FROM memberships m
      JOIN organizations o
        ON o.id = m.org_id
      WHERE m.user_id = ?
        AND m.status = 'active'
        AND o.deleted_at IS NULL
      ORDER BY o.name
    `).all(ctx.userId);

    send(res, 200, { orgs });
  };
}


// -----------------------------------------------------------------------------
// POST /v1/orgs
// -----------------------------------------------------------------------------

function createOrg({ db }) {
  return async function handler(ctx, params, res) {
    const name =
      typeof ctx.body.name === 'string'
        ? ctx.body.name.trim()
        : '';

    if (!name) {
      throw badRequest('organization name is required');
    }

    const orgId = newId('org');
    const membershipId = newId('mem');

    const theme = `theme-${orgId.slice(-6)}`;

    const tx = db.transaction(() => {
      db.prepare(`
        INSERT INTO organizations (
          id,
          name,
          theme,
          max_session_minutes
        )
        VALUES (?, ?, ?, 60)
      `).run(
        orgId,
        name,
        theme
      );

      db.prepare(`
        INSERT INTO memberships (
          id,
          org_id,
          user_id,
          role,
          status,
          joined_at
        )
        VALUES (?, ?, ?, 'owner', 'active', ?)
      `).run(
        membershipId,
        orgId,
        ctx.userId,
        new Date().toISOString()
      );
    });

    tx();

    send(res, 201, {
      id: orgId,
      name,
      theme,
      role: 'owner',
    });
  };
}


// -----------------------------------------------------------------------------
// GET members
// -----------------------------------------------------------------------------

function listMembers({ db }) {
  return async function handler(ctx, params, res) {
    assertCan(db, ctx, 'user:read');

    const members = db.prepare(`
      SELECT
        u.id,
        u.email,
        u.name,
        m.role,
        m.status,
        m.joined_at
      FROM memberships m
      JOIN users u
        ON u.id = m.user_id
      WHERE m.org_id = ?
        AND m.status <> 'removed'
      ORDER BY u.name
    `).all(ctx.orgId);

    send(res, 200, { members });
  };
}


// -----------------------------------------------------------------------------
// PATCH member role
// -----------------------------------------------------------------------------

function updateMemberRole({ db }) {
  return async function handler(ctx, params, res) {
    assertCan(
      db,
      ctx,
      'user:role:update'
    );

    const targetUserId = params.userId;

    if (targetUserId === ctx.userId) {
      throw selfRoleChange();
    }

    const target = db.prepare(`
      SELECT
        id,
        role,
        status,
        perm_version
      FROM memberships
      WHERE org_id = ?
        AND user_id = ?
        AND status <> 'removed'
      LIMIT 1
    `).get(
      ctx.orgId,
      targetUserId
    );

    if (!target) {
      throw notFound();
    }

    const newRole =
      typeof ctx.body.role === 'string'
        ? ctx.body.role
        : '';

    assertRoleExists(db, newRole);

    assertCanModify(
      db,
      ctx.role,
      target.role
    );

    // Only an owner may assign owner.
    if (
      newRole === 'owner' &&
      ctx.role !== 'owner'
    ) {
      throw forbidden('only an owner may assign owner');
    }

    // Don't allow assigning a role above the caller.
    const ranks = roleRanks(db);

    if (
      ctx.role !== 'owner' &&
      ranks[newRole] >= ranks[ctx.role]
    ) {
      throw forbidden('cannot assign this role');
    }

    // Demoting an owner cannot remove the final owner.
    if (
      target.role === 'owner' &&
      newRole !== 'owner'
    ) {
      assertNotLastOwner(
        db,
        ctx.orgId,
        targetUserId
      );
    }

    // IMPORTANT:
    // role changes invalidate future requests...
    db.prepare(`
      UPDATE memberships
      SET
        role = ?,
        perm_version = perm_version + 1
      WHERE org_id = ?
        AND user_id = ?
    `).run(
      newRole,
      ctx.orgId,
      targetUserId
    );

    // ...but DO NOT end existing sessions.
    // That is session grandfathering.

    const updated = db.prepare(`
      SELECT
        user_id,
        role,
        status,
        perm_version
      FROM memberships
      WHERE org_id = ?
        AND user_id = ?
    `).get(
      ctx.orgId,
      targetUserId
    );

    send(res, 200, updated);
  };
}


// -----------------------------------------------------------------------------
// Suspend
// -----------------------------------------------------------------------------

function suspendMember({ db }) {
  return async function handler(ctx, params, res) {
    assertCan(db, ctx, 'user:remove');

    const targetUserId = params.userId;

    const target = db.prepare(`
      SELECT role, status
      FROM memberships
      WHERE org_id = ?
        AND user_id = ?
        AND status <> 'removed'
      LIMIT 1
    `).get(
      ctx.orgId,
      targetUserId
    );

    if (!target) {
      throw notFound();
    }

    assertCanModify(
      db,
      ctx.role,
      target.role
    );

    if (target.role === 'owner') {
      assertNotLastOwner(
        db,
        ctx.orgId,
        targetUserId
      );
    }

    db.prepare(`
      UPDATE memberships
      SET
        status = 'suspended',
        perm_version = perm_version + 1
      WHERE org_id = ?
        AND user_id = ?
    `).run(
      ctx.orgId,
      targetUserId
    );

    // Suspension DOES terminate live sessions.
    endActiveSessions(db, {
      orgId: ctx.orgId,
      userId: targetUserId,
      reason: 'user_suspended',
    });

    send(res, 200, {
      userId: targetUserId,
      status: 'suspended',
    });
  };
}


// -----------------------------------------------------------------------------
// Reinstate
// -----------------------------------------------------------------------------

function reinstateMember({ db }) {
  return async function handler(ctx, params, res) {
    assertCan(db, ctx, 'user:remove');

    const targetUserId = params.userId;

    const target = db.prepare(`
      SELECT role, status
      FROM memberships
      WHERE org_id = ?
        AND user_id = ?
      LIMIT 1
    `).get(
      ctx.orgId,
      targetUserId
    );

    if (
      !target ||
      target.status !== 'suspended'
    ) {
      throw notFound();
    }

    assertCanModify(
      db,
      ctx.role,
      target.role
    );

    db.prepare(`
      UPDATE memberships
      SET
        status = 'active',
        perm_version = perm_version + 1
      WHERE org_id = ?
        AND user_id = ?
    `).run(
      ctx.orgId,
      targetUserId
    );

    send(res, 200, {
      userId: targetUserId,
      status: 'active',
    });
  };
}


// -----------------------------------------------------------------------------
// Remove member
// -----------------------------------------------------------------------------

function removeMember({ db }) {
  return async function handler(ctx, params, res) {
    assertCan(db, ctx, 'user:remove');

    const targetUserId = params.userId;

    const target = db.prepare(`
      SELECT role, status
      FROM memberships
      WHERE org_id = ?
        AND user_id = ?
        AND status <> 'removed'
      LIMIT 1
    `).get(
      ctx.orgId,
      targetUserId
    );

    if (!target) {
      throw notFound();
    }

    assertCanModify(
      db,
      ctx.role,
      target.role
    );

    if (target.role === 'owner') {
      assertNotLastOwner(
        db,
        ctx.orgId,
        targetUserId
      );
    }

    db.prepare(`
      UPDATE memberships
      SET
        status = 'removed',
        perm_version = perm_version + 1
      WHERE org_id = ?
        AND user_id = ?
    `).run(
      ctx.orgId,
      targetUserId
    );

    endActiveSessions(db, {
      orgId: ctx.orgId,
      userId: targetUserId,
      reason: 'membership_removed',
    });

    send(res, 200, {
      userId: targetUserId,
      status: 'removed',
    });
  };
}


// -----------------------------------------------------------------------------
// Leave organization
// -----------------------------------------------------------------------------

function leaveOrg({ db }) {
  return async function handler(ctx, params, res) {
    assertNotLastOwner(
      db,
      ctx.orgId,
      ctx.userId
    );

    db.prepare(`
      UPDATE memberships
      SET
        status = 'removed',
        perm_version = perm_version + 1
      WHERE org_id = ?
        AND user_id = ?
    `).run(
      ctx.orgId,
      ctx.userId
    );

    endActiveSessions(db, {
      orgId: ctx.orgId,
      userId: ctx.userId,
      reason: 'membership_removed',
    });

    send(res, 200, {
      status: 'removed',
    });
  };
}


// -----------------------------------------------------------------------------
// Register
// -----------------------------------------------------------------------------

export function registerOrgRoutes(router, deps) {
  router.get(
    '/v1/orgs',
    listOrgs(deps)
  );

  router.post(
    '/v1/orgs',
    createOrg(deps)
  );

  router.get(
    '/v1/orgs/:org/members',
    listMembers(deps)
  );

  // IMPORTANT: specific `me` route before :userId
  router.delete(
    '/v1/orgs/:org/members/me',
    leaveOrg(deps)
  );

  router.post(
    '/v1/orgs/:org/members/:userId/suspend',
    suspendMember(deps)
  );

  router.delete(
    '/v1/orgs/:org/members/:userId/suspend',
    reinstateMember(deps)
  );

  router.patch(
    '/v1/orgs/:org/members/:userId',
    updateMemberRole(deps)
  );

  router.delete(
    '/v1/orgs/:org/members/:userId',
    removeMember(deps)
  );
}