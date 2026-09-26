import { send } from '../http.js';
import {
  assertCan,
  resolveDevices,
} from '../permissions.js';


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
// Registration
// -----------------------------------------------------------------------------

export function registerDeviceRoutes(router, deps) {
  router.get(
    '/v1/orgs/:org/devices',
    listDevices(deps)
  );
}