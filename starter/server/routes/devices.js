import {
  send,
  notFound,
  badRequest,
  forbidden,
} from '../http.js';

import {
  newId,
} from '../db.js';

import {
  assertCan,
  resolve,
  resolveDevices,
} from '../permissions.js';

import {
  audit,
  auditDenials,
} from '../audit.js';

import {
  endActiveSessions,
} from '../lifecycle.js';


const VALID_KINDS = new Set([
  'macos',
  'windows',
  'linux',
  'android',
  'ios',
]);


// -----------------------------------------------------------------------------
// GET /v1/orgs/:org/devices
// -----------------------------------------------------------------------------

function listDevices({ db }) {
  return async function listDevicesHandler(ctx, params, res) {
    // The request pipeline has already authenticated the caller and
    // context.js has already enforced that params.org matches ctx.orgId.

    // First gate the endpoint itself.
    assertCan(
      db,
      ctx,
      'device:list'
    );

    const devices = db.prepare(`
      SELECT
        id,
        org_id,
        name,
        kind,
        online,
        created_at
      FROM devices
      WHERE org_id = ?
        AND deleted_at IS NULL
      ORDER BY name ASC
    `).all(ctx.orgId);

    const deviceIds = devices.map(
      (device) => device.id
    );

    // Resolve permissions once for all device rows.
    const resolved = resolveDevices(db, {
      userId: ctx.userId,
      orgId: ctx.orgId,
      deviceIds,
    });

    const visibleDevices = [];

    for (const device of devices) {
      const permissions =
        resolved.byDevice[device.id];

      // device:view controls ROW VISIBILITY.
      //
      // If denied, the device is absent completely.
      if (
        permissions['device:view']?.effect !==
        'allow'
      ) {
        continue;
      }

      visibleDevices.push({
        id: device.id,
        name: device.name,
        kind: device.kind,
        online: Boolean(device.online),
        permissions,
      });
    }

    send(res, 200, {
      devices: visibleDevices,
    });
  };
}


// -----------------------------------------------------------------------------
// GET /v1/orgs/:org/devices/:id
// -----------------------------------------------------------------------------

function getDevice({ db }) {
  return async function getDeviceHandler(ctx, params, res) {
    const deviceId = params.id;

    const device = db.prepare(`
      SELECT
        id,
        org_id,
        name,
        kind,
        online,
        created_at
      FROM devices
      WHERE id = ?
        AND org_id = ?
        AND deleted_at IS NULL
      LIMIT 1
    `).get(deviceId, ctx.orgId);

    if (!device) {
      throw notFound();
    }

    // Checking device:view on this exact device
    assertCan(db, ctx, 'device:view', deviceId);

    const resolved = resolve(db, {
      userId: ctx.userId,
      orgId: ctx.orgId,
      deviceId,
    });

    send(res, 200, {
      id: device.id,
      name: device.name,
      kind: device.kind,
      online: Boolean(device.online),
      createdAt: device.created_at,
      permissions: resolved.permissions,
    });
  };
}


// -----------------------------------------------------------------------------
// POST /v1/orgs/:org/devices
// -----------------------------------------------------------------------------

function createDevice({ db }) {
  return async function createDeviceHandler(ctx, params, res) {
    return auditDenials(
      db,
      ctx,
      {
        action: 'device:provision',
        targetType: 'device',
        targetId: null,
      },
      () => {
        assertCan(db, ctx, 'device:provision');

        const name = typeof ctx.body?.name === 'string' ? ctx.body.name.trim() : '';
        const kind = typeof ctx.body?.kind === 'string' ? ctx.body.kind.trim().toLowerCase() : '';
        const online = ctx.body?.online ? 1 : 0;

        if (!name) {
          throw badRequest('device name is required');
        }

        if (!VALID_KINDS.has(kind)) {
          throw badRequest(`invalid device kind: ${kind}`);
        }

        const id = newId('dev');

        const tx = db.transaction(() => {
          db.prepare(`
            INSERT INTO devices (
              id,
              org_id,
              name,
              kind,
              online
            )
            VALUES (?, ?, ?, ?, ?)
          `).run(id, ctx.orgId, name, kind, online);

          audit(db, {
            orgId: ctx.orgId,
            actorId: ctx.userId,
            action: 'device:provision',
            targetType: 'device',
            targetId: id,
            result: 'allow',
            reasonCode: null,
            requestId: ctx.requestId,
          });
        });

        tx();

        const created = db.prepare(`
          SELECT id, org_id, name, kind, online, created_at
          FROM devices
          WHERE id = ?
        `).get(id);

        send(res, 201, {
          id: created.id,
          name: created.name,
          kind: created.kind,
          online: Boolean(created.online),
          createdAt: created.created_at,
        });
      }
    );
  };
}


// -----------------------------------------------------------------------------
// PATCH /v1/orgs/:org/devices/:id
// -----------------------------------------------------------------------------

function updateDevice({ db }) {
  return async function updateDeviceHandler(ctx, params, res) {
    const deviceId = params.id;

    const device = db.prepare(`
      SELECT id, org_id, name, kind, online, created_at
      FROM devices
      WHERE id = ?
        AND org_id = ?
        AND deleted_at IS NULL
      LIMIT 1
    `).get(deviceId, ctx.orgId);

    if (!device) {
      throw notFound();
    }

    return auditDenials(
      db,
      ctx,
      {
        action: 'device:update',
        targetType: 'device',
        targetId: deviceId,
      },
      () => {
        assertCan(db, ctx, 'device:update', deviceId);

        const name = typeof ctx.body?.name === 'string' ? ctx.body.name.trim() : null;
        const online = ctx.body?.online !== undefined ? (ctx.body.online ? 1 : 0) : null;

        if (name === null && online === null) {
          throw badRequest('name or online state is required');
        }

        if (name !== null && !name) {
          throw badRequest('device name cannot be empty');
        }

        const updates = [];
        const args = [];

        if (name !== null) {
          updates.push('name = ?');
          args.push(name);
        }

        if (online !== null) {
          updates.push('online = ?');
          args.push(online);
        }

        args.push(deviceId, ctx.orgId);

        const tx = db.transaction(() => {
          db.prepare(`
            UPDATE devices
            SET ${updates.join(', ')}
            WHERE id = ?
              AND org_id = ?
              AND deleted_at IS NULL
          `).run(...args);

          audit(db, {
            orgId: ctx.orgId,
            actorId: ctx.userId,
            action: 'device:update',
            targetType: 'device',
            targetId: deviceId,
            result: 'allow',
            reasonCode: null,
            requestId: ctx.requestId,
          });
        });

        tx();

        const updated = db.prepare(`
          SELECT id, org_id, name, kind, online, created_at
          FROM devices
          WHERE id = ?
        `).get(deviceId);

        send(res, 200, {
          id: updated.id,
          name: updated.name,
          kind: updated.kind,
          online: Boolean(updated.online),
          createdAt: updated.created_at,
        });
      }
    );
  };
}


// -----------------------------------------------------------------------------
// DELETE /v1/orgs/:org/devices/:id
// -----------------------------------------------------------------------------

function deleteDevice({ db }) {
  return async function deleteDeviceHandler(ctx, params, res) {
    const deviceId = params.id;

    const device = db.prepare(`
      SELECT id
      FROM devices
      WHERE id = ?
        AND org_id = ?
        AND deleted_at IS NULL
      LIMIT 1
    `).get(deviceId, ctx.orgId);

    if (!device) {
      throw notFound();
    }

    return auditDenials(
      db,
      ctx,
      {
        action: 'device:provision',
        targetType: 'device',
        targetId: deviceId,
      },
      () => {
        // Decommission requires device:provision (per BRIEF.md §5.1)
        assertCan(db, ctx, 'device:provision', deviceId);

        const now = new Date().toISOString();

        const tx = db.transaction(() => {
          db.prepare(`
            UPDATE devices
            SET deleted_at = ?
            WHERE id = ?
          `).run(now, deviceId);

          // Decommissioning terminates active sessions on this device with reason device_transferred
          endActiveSessions(db, {
            orgId: ctx.orgId,
            deviceId,
            reason: 'device_transferred',
          });

          audit(db, {
            orgId: ctx.orgId,
            actorId: ctx.userId,
            action: 'device:provision',
            targetType: 'device',
            targetId: deviceId,
            result: 'allow',
            reasonCode: 'decommission',
            requestId: ctx.requestId,
          });
        });

        tx();

        send(res, 200, {
          id: deviceId,
          deleted: true,
        });
      }
    );
  };
}


// -----------------------------------------------------------------------------
// POST /v1/orgs/:org/devices/:id/transfer
// -----------------------------------------------------------------------------

function transferDevice({ db }) {
  return async function transferDeviceHandler(ctx, params, res) {
    const deviceId = params.id;
    const targetOrgId = typeof ctx.body?.targetOrgId === 'string' ? ctx.body.targetOrgId.trim() : '';

    if (!targetOrgId) {
      throw badRequest('targetOrgId is required');
    }

    const device = db.prepare(`
      SELECT id, name
      FROM devices
      WHERE id = ?
        AND org_id = ?
        AND deleted_at IS NULL
      LIMIT 1
    `).get(deviceId, ctx.orgId);

    if (!device) {
      throw notFound();
    }

    // Verify target organization exists
    const targetOrg = db.prepare(`
      SELECT id
      FROM organizations
      WHERE id = ?
        AND deleted_at IS NULL
      LIMIT 1
    `).get(targetOrgId);

    if (!targetOrg) {
      throw badRequest('target organization not found');
    }

    return auditDenials(
      db,
      ctx,
      {
        action: 'device:provision',
        targetType: 'device',
        targetId: deviceId,
      },
      () => {
        // 1. Caller needs device:provision in current org
        assertCan(db, ctx, 'device:provision', deviceId);

        // 2. Caller needs device:provision in destination org
        const destMembership = db.prepare(`
          SELECT role, status
          FROM memberships
          WHERE org_id = ?
            AND user_id = ?
            AND status = 'active'
          LIMIT 1
        `).get(targetOrgId, ctx.userId);

        if (!destMembership) {
          throw forbidden('must have active membership in target organization');
        }

        const destCtx = {
          userId: ctx.userId,
          orgId: targetOrgId,
          role: destMembership.role,
        };

        assertCan(db, destCtx, 'device:provision');

        const tx = db.transaction(() => {
          // Transfer device
          db.prepare(`
            UPDATE devices
            SET org_id = ?
            WHERE id = ?
          `).run(targetOrgId, deviceId);

          // End active sessions on this device with reason device_transferred
          endActiveSessions(db, {
            orgId: ctx.orgId,
            deviceId,
            reason: 'device_transferred',
          });

          // Audit in source org
          audit(db, {
            orgId: ctx.orgId,
            actorId: ctx.userId,
            action: 'device:provision',
            targetType: 'device',
            targetId: deviceId,
            result: 'allow',
            reasonCode: 'transfer_out',
            requestId: ctx.requestId,
          });

          // Audit in target org
          audit(db, {
            orgId: targetOrgId,
            actorId: ctx.userId,
            action: 'device:provision',
            targetType: 'device',
            targetId: deviceId,
            result: 'allow',
            reasonCode: 'transfer_in',
            requestId: ctx.requestId,
          });
        });

        tx();

        send(res, 200, {
          id: deviceId,
          orgId: targetOrgId,
          transferred: true,
        });
      }
    );
  };
}


// -----------------------------------------------------------------------------
// Registration
// -----------------------------------------------------------------------------

export function registerDeviceRoutes(router, deps) {
  router.get(
    '/v1/orgs/:org/devices',
    listDevices(deps)
  );

  router.post(
    '/v1/orgs/:org/devices',
    createDevice(deps)
  );

  router.get(
    '/v1/orgs/:org/devices/:id',
    getDevice(deps)
  );

  router.patch(
    '/v1/orgs/:org/devices/:id',
    updateDevice(deps)
  );

  router.delete(
    '/v1/orgs/:org/devices/:id',
    deleteDevice(deps)
  );

  router.post(
    '/v1/orgs/:org/devices/:id/transfer',
    transferDevice(deps)
  );
}