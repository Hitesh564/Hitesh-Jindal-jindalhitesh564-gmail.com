import {
  send,
  badRequest,
  notFound,
  forbidden,
  HttpError,
  normalizeTs,
} from '../http.js';

import {
  assertCan,
  assertMayGrant,
} from '../permissions.js';

import {
  newId,
  bumpPermVersion,
} from '../db.js';


// -----------------------------------------------------------------------------
// POST /v1/orgs/:org/grants
// -----------------------------------------------------------------------------

function createGrant({ db }) {
  return async function handler(ctx, params, res) {
    assertCan(db, ctx, 'grant:create');

    const {
      userId,
      deviceId = null,
      effect,
      permissions,
      startsAt = null,
      expiresAt = null,
    } = ctx.body;


    // No self-grants.
    if (userId === ctx.userId) {
      throw forbidden(
        'cannot grant permissions to yourself',
        'self_grant'
      );
    }


    if (!['allow', 'deny'].includes(effect)) {
      throw badRequest('effect must be allow or deny');
    }


    if (
      !Array.isArray(permissions) ||
      permissions.length === 0
    ) {
      throw badRequest(
        'permissions must be a non-empty array'
      );
    }


    if (
      permissions.some(
        (p) => typeof p !== 'string' || !p
      )
    ) {
      throw badRequest('invalid permission');
    }


    // Validate target membership.
    const target = db.prepare(`
      SELECT user_id, status
      FROM memberships
      WHERE org_id = ?
        AND user_id = ?
        AND status = 'active'
      LIMIT 1
    `).get(
      ctx.orgId,
      userId
    );

    if (!target) {
      throw notFound();
    }


    // Device must belong to this org.
    if (deviceId !== null) {
      const device = db.prepare(`
        SELECT id
        FROM devices
        WHERE id = ?
          AND org_id = ?
          AND deleted_at IS NULL
        LIMIT 1
      `).get(
        deviceId,
        ctx.orgId
      );

      if (!device) {
        throw notFound();
      }
    }


    // Explicitly validate permission patterns so we can return the
    // required 400 reason rather than exposing a raw FK error.
    const validPatterns = new Set(
      db.prepare(`
        SELECT pattern
        FROM permission_patterns
      `).all().map((row) => row.pattern)
    );

    for (const permission of permissions) {
      if (!validPatterns.has(permission)) {
        throw badRequest(
          `unknown permission: ${permission}`,
          'unknown_permission'
        );
      }
    }


    const starts =
      normalizeTs(startsAt, 'startsAt');

    const expires =
      normalizeTs(expiresAt, 'expiresAt');


    if (
      expires &&
      expires <= new Date().toISOString()
    ) {
      throw new HttpError(
        400,
        'GRANT_EXPIRED',
        'grant expiry must be in the future',
        'expired_grant'
      );
    }


    if (
      starts &&
      expires &&
      expires <= starts
    ) {
      throw badRequest(
        'expiresAt must be after startsAt'
      );
    }


    // D9: caller cannot grant authority they do not hold.
    assertMayGrant(
      db,
      ctx,
      permissions,
      deviceId
    );


    const id = newId('grt');

    const tx = db.transaction(() => {
      db.prepare(`
        INSERT INTO grants (
          id,
          org_id,
          user_id,
          device_id,
          effect,
          starts_at,
          expires_at,
          created_by
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        id,
        ctx.orgId,
        userId,
        deviceId,
        effect,
        starts,
        expires,
        ctx.userId
      );


      const insertPermission = db.prepare(`
        INSERT INTO grant_permissions (
          grant_id,
          permission
        )
        VALUES (?, ?)
      `);

      for (const permission of new Set(permissions)) {
        insertPermission.run(
          id,
          permission
        );
      }


      bumpPermVersion(db, {
        orgId: ctx.orgId,
        userId,
      });
    });

    tx();


    send(res, 201, {
      id,
      userId,
      deviceId,
      effect,
      permissions: [...new Set(permissions)],
      startsAt: starts,
      expiresAt: expires,
    });
  };
}


// -----------------------------------------------------------------------------
// GET grants
// -----------------------------------------------------------------------------

function listGrants({ db }) {
  return async function handler(ctx, params, res) {
    assertCan(db, ctx, 'user:read');

    const rows = db.prepare(`
      SELECT
        g.id,
        g.user_id,
        g.device_id,
        g.effect,
        g.starts_at,
        g.expires_at,
        g.created_by,
        g.created_at,
        gp.permission
      FROM grants g
      JOIN grant_permissions gp
        ON gp.grant_id = g.id
      WHERE g.org_id = ?
        AND g.revoked_at IS NULL
      ORDER BY g.created_at DESC, g.id
    `).all(ctx.orgId);


    const map = new Map();

    for (const row of rows) {
      if (!map.has(row.id)) {
        map.set(row.id, {
          id: row.id,
          userId: row.user_id,
          deviceId: row.device_id,
          effect: row.effect,
          startsAt: row.starts_at,
          expiresAt: row.expires_at,
          createdBy: row.created_by,
          permissions: [],
        });
      }

      map.get(row.id).permissions.push(
        row.permission
      );
    }


    send(res, 200, {
      grants: [...map.values()],
    });
  };
}


// -----------------------------------------------------------------------------
// DELETE grant
// -----------------------------------------------------------------------------

function revokeGrant({ db }) {
  return async function handler(ctx, params, res) {
    assertCan(db, ctx, 'grant:revoke');

    const grant = db.prepare(`
      SELECT
        id,
        user_id
      FROM grants
      WHERE id = ?
        AND org_id = ?
        AND revoked_at IS NULL
      LIMIT 1
    `).get(
      params.id,
      ctx.orgId
    );

    if (!grant) {
      throw notFound();
    }


    const tx = db.transaction(() => {
      db.prepare(`
        UPDATE grants
        SET revoked_at = ?
        WHERE id = ?
      `).run(
        new Date().toISOString(),
        grant.id
      );

      bumpPermVersion(db, {
        orgId: ctx.orgId,
        userId: grant.user_id,
      });
    });

    tx();


    send(res, 200, {
      id: grant.id,
      revoked: true,
    });
  };
}


export function registerGrantRoutes(router, deps) {
  router.post(
    '/v1/orgs/:org/grants',
    createGrant(deps)
  );

  router.get(
    '/v1/orgs/:org/grants',
    listGrants(deps)
  );

  router.delete(
    '/v1/orgs/:org/grants/:id',
    revokeGrant(deps)
  );
}