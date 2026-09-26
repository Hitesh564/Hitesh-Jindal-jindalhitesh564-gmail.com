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
  resolve,
} from '../permissions.js';

import {
  audit,
  auditDenials,
} from '../audit.js';

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

      audit(db, {
        orgId,
        actorId: ctx.userId,
        action: 'org:create',
        targetType: 'org',
        targetId: orgId,
        result: 'allow',
        reasonCode: null,
        requestId: ctx.requestId,
      });
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
    const targetUserId = params.userId;

    return auditDenials(
      db,
      ctx,
      {
        action: 'user:role:update',
        targetType: 'user',
        targetId: targetUserId,
      },
      () => {
        assertCan(
          db,
          ctx,
          'user:role:update'
        );

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
        const tx = db.transaction(() => {
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

          audit(db, {
            orgId: ctx.orgId,
            actorId: ctx.userId,
            action: 'user:role:update',
            targetType: 'user',
            targetId: targetUserId,
            result: 'allow',
            reasonCode: newRole,
            requestId: ctx.requestId,
          });
        });

        tx();

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
      }
    );
  };
}


// -----------------------------------------------------------------------------
// Suspend
// -----------------------------------------------------------------------------

function suspendMember({ db }) {
  return async function handler(ctx, params, res) {
    const targetUserId = params.userId;

    return auditDenials(
      db,
      ctx,
      {
        action: 'user:remove',
        targetType: 'user',
        targetId: targetUserId,
      },
      () => {
        assertCan(db, ctx, 'user:remove');

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

        const tx = db.transaction(() => {
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

          audit(db, {
            orgId: ctx.orgId,
            actorId: ctx.userId,
            action: 'user:remove',
            targetType: 'user',
            targetId: targetUserId,
            result: 'allow',
            reasonCode: 'suspended',
            requestId: ctx.requestId,
          });
        });

        tx();

        send(res, 200, {
          userId: targetUserId,
          status: 'suspended',
        });
      }
    );
  };
}


// -----------------------------------------------------------------------------
// Reinstate
// -----------------------------------------------------------------------------

function reinstateMember({ db }) {
  return async function handler(ctx, params, res) {
    const targetUserId = params.userId;

    return auditDenials(
      db,
      ctx,
      {
        action: 'user:remove',
        targetType: 'user',
        targetId: targetUserId,
      },
      () => {
        assertCan(db, ctx, 'user:remove');

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

        const tx = db.transaction(() => {
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

          audit(db, {
            orgId: ctx.orgId,
            actorId: ctx.userId,
            action: 'user:remove',
            targetType: 'user',
            targetId: targetUserId,
            result: 'allow',
            reasonCode: 'reinstated',
            requestId: ctx.requestId,
          });
        });

        tx();

        send(res, 200, {
          userId: targetUserId,
          status: 'active',
        });
      }
    );
  };
}


// -----------------------------------------------------------------------------
// Remove member
// -----------------------------------------------------------------------------

function removeMember({ db }) {
  return async function handler(ctx, params, res) {
    const targetUserId = params.userId;

    return auditDenials(
      db,
      ctx,
      {
        action: 'user:remove',
        targetType: 'user',
        targetId: targetUserId,
      },
      () => {
        assertCan(db, ctx, 'user:remove');

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

        const tx = db.transaction(() => {
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

          audit(db, {
            orgId: ctx.orgId,
            actorId: ctx.userId,
            action: 'user:remove',
            targetType: 'user',
            targetId: targetUserId,
            result: 'allow',
            reasonCode: 'removed',
            requestId: ctx.requestId,
          });
        });

        tx();

        send(res, 200, {
          userId: targetUserId,
          status: 'removed',
        });
      }
    );
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

    const tx = db.transaction(() => {
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

      audit(db, {
        orgId: ctx.orgId,
        actorId: ctx.userId,
        action: 'user:remove',
        targetType: 'user',
        targetId: ctx.userId,
        result: 'allow',
        reasonCode: 'left_org',
        requestId: ctx.requestId,
      });
    });

    tx();

    send(res, 200, {
      status: 'removed',
    });
  };
}


// -----------------------------------------------------------------------------
// PATCH /v1/orgs/:org
// -----------------------------------------------------------------------------

function updateOrg({ db }) {
  return async function updateOrgHandler(ctx, params, res) {
    return auditDenials(
      db,
      ctx,
      {
        action: 'org:update',
        targetType: 'org',
        targetId: ctx.orgId,
      },
      () => {
        assertCan(db, ctx, 'org:update');

        const name = typeof ctx.body?.name === 'string' ? ctx.body.name.trim() : null;
        const theme = typeof ctx.body?.theme === 'string' ? ctx.body.theme.trim() : null;

        if (name === null && theme === null) {
          throw badRequest('name or theme is required to update');
        }

        if (name !== null && !name) {
          throw badRequest('organization name cannot be empty');
        }

        const updates = [];
        const args = [];

        if (name !== null) {
          updates.push('name = ?');
          args.push(name);
        }

        if (theme !== null) {
          updates.push('theme = ?');
          args.push(theme);
        }

        args.push(ctx.orgId);

        const tx = db.transaction(() => {
          db.prepare(`
            UPDATE organizations
            SET ${updates.join(', ')}
            WHERE id = ?
              AND deleted_at IS NULL
          `).run(...args);

          audit(db, {
            orgId: ctx.orgId,
            actorId: ctx.userId,
            action: 'org:update',
            targetType: 'org',
            targetId: ctx.orgId,
            result: 'allow',
            reasonCode: null,
            requestId: ctx.requestId,
          });
        });

        tx();

        const updated = db.prepare(`
          SELECT id, name, theme, max_session_minutes, created_at
          FROM organizations
          WHERE id = ?
        `).get(ctx.orgId);

        send(res, 200, updated);
      }
    );
  };
}


// -----------------------------------------------------------------------------
// DELETE /v1/orgs/:org
// -----------------------------------------------------------------------------

function deleteOrg({ db }) {
  return async function deleteOrgHandler(ctx, params, res) {
    return auditDenials(
      db,
      ctx,
      {
        action: 'org:delete',
        targetType: 'org',
        targetId: ctx.orgId,
      },
      () => {
        assertCan(db, ctx, 'org:delete');

        const now = new Date().toISOString();

        const tx = db.transaction(() => {
          // Soft-delete the organization
          db.prepare(`
            UPDATE organizations
            SET deleted_at = ?
            WHERE id = ?
              AND deleted_at IS NULL
          `).run(now, ctx.orgId);

          // Invalidate all memberships in the org
          db.prepare(`
            UPDATE memberships
            SET status = 'removed',
                perm_version = perm_version + 1
            WHERE org_id = ?
              AND status <> 'removed'
          `).run(ctx.orgId);

          // End all live sessions in the org
          endActiveSessions(db, {
            orgId: ctx.orgId,
            reason: 'membership_removed',
          });

          // Soft delete all devices in the org
          db.prepare(`
            UPDATE devices
            SET deleted_at = ?
            WHERE org_id = ?
              AND deleted_at IS NULL
          `).run(now, ctx.orgId);

          audit(db, {
            orgId: ctx.orgId,
            actorId: ctx.userId,
            action: 'org:delete',
            targetType: 'org',
            targetId: ctx.orgId,
            result: 'allow',
            reasonCode: null,
            requestId: ctx.requestId,
          });
        });

        tx();

        send(res, 200, {
          id: ctx.orgId,
          deleted: true,
        });
      }
    );
  };
}


// -----------------------------------------------------------------------------
// GET /v1/orgs/:org/users/:userId/effective
// -----------------------------------------------------------------------------

function getEffectivePermissions({ db }) {
  return async function getEffectivePermissionsHandler(ctx, params, res) {
    const targetUserId = params.userId;

    // Caller can view self, or needs user:read
    if (targetUserId !== ctx.userId) {
      assertCan(db, ctx, 'user:read');
    }

    const membership = db.prepare(`
      SELECT role, status
      FROM memberships
      WHERE org_id = ?
        AND user_id = ?
        AND status <> 'removed'
      LIMIT 1
    `).get(ctx.orgId, targetUserId);

    if (!membership) {
      throw notFound();
    }

    const resolved = resolve(db, {
      userId: targetUserId,
      orgId: ctx.orgId,
    });

    send(res, 200, {
      role: membership.role,
      permissions: resolved.permissions,
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

  router.patch(
    '/v1/orgs/:org',
    updateOrg(deps)
  );

  router.delete(
    '/v1/orgs/:org',
    deleteOrg(deps)
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

  router.get(
    '/v1/orgs/:org/users/:userId/effective',
    getEffectivePermissions(deps)
  );
}