import { forbidden, badRequest } from './http.js';

export const MODE_PERMISSION = {
  view: 'device:view',
  control: 'device:control',
  terminal: 'device:terminal',
};


// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

function patternMatches(pattern, permission) {
  if (pattern === '*') return true;

  if (pattern === permission) return true;

  if (pattern.endsWith(':*')) {
    const resource = pattern.slice(0, -2);
    return permission.startsWith(`${resource}:`);
  }

  return false;
}


function loadState(db, { userId, orgId }) {
  // IMPORTANT:
  // Read the permission catalogue from the DB.
  // Never hard-code the documented 19 permissions.
  const catalogue = db.prepare(`
    SELECT key, resource, action
    FROM permissions
    ORDER BY key
  `).all();

  const membership = db.prepare(`
    SELECT
      id,
      org_id,
      user_id,
      role,
      status,
      perm_version
    FROM memberships
    WHERE org_id = ?
      AND user_id = ?
    LIMIT 1
  `).get(orgId, userId);

  if (!membership) {
    return {
      catalogue,
      membership: null,
      baseline: new Set(),
      grants: [],
    };
  }

  // Role baseline also comes completely from the DB.
  const baselineRows = db.prepare(`
    SELECT permission
    FROM role_permissions
    WHERE role = ?
  `).all(membership.role);

  const baseline = new Set(
    baselineRows.map((row) => row.permission)
  );

  // Load all active/non-revoked grants for this user in this org.
  // Time-window filtering is handled during resolution because `now`
  // is supplied to resolve().
  const grantRows = db.prepare(`
    SELECT
      g.id,
      g.org_id,
      g.user_id,
      g.device_id,
      g.effect,
      g.starts_at,
      g.expires_at,
      g.revoked_at,
      gp.permission AS pattern
    FROM grants g
    JOIN grant_permissions gp
      ON gp.grant_id = g.id
    WHERE g.org_id = ?
      AND g.user_id = ?
      AND g.revoked_at IS NULL
    ORDER BY g.created_at, g.id
  `).all(orgId, userId);

  return {
    catalogue,
    membership,
    baseline,
    grants: grantRows,
  };
}


function activeAt(grant, nowIso) {
  // Half-open interval:
  //
  // starts_at <= now < expires_at
  //
  // So expires_at == now is already expired.

  if (grant.starts_at && grant.starts_at > nowIso) {
    return false;
  }

  if (grant.expires_at && grant.expires_at <= nowIso) {
    return false;
  }

  return true;
}


function emptyPermissionSet(catalogue, reason) {
  const permissions = {};

  for (const permission of catalogue) {
    permissions[permission.key] = {
      effect: 'deny',
      source: null,
      reason,
    };
  }

  return permissions;
}


// Resolve at one exact scope.
//
// deviceId === null here means:
// use only org-wide grants.
//
// Device-specific grants are considered only when a device is supplied.
function resolveExact(state, deviceId, nowIso) {
  const { catalogue, baseline, grants } = state;

  const permissions = {};

  for (const permissionRow of catalogue) {
    const permission = permissionRow.key;

    const applicable = grants.filter((grant) => {
      if (!activeAt(grant, nowIso)) {
        return false;
      }

      // At an exact device:
      // org-wide grants + grants for this device apply.
      //
      // At null:
      // only org-wide grants apply.
      if (deviceId === null) {
        if (grant.device_id !== null) {
          return false;
        }
      } else {
        if (
          grant.device_id !== null &&
          grant.device_id !== deviceId
        ) {
          return false;
        }
      }

      return patternMatches(grant.pattern, permission);
    });


    // -----------------------------------------------------------------------
    // D1 — explicit deny ALWAYS wins.
    // -----------------------------------------------------------------------

    const denyingGrant = applicable.find(
      (grant) => grant.effect === 'deny'
    );

    if (denyingGrant) {
      permissions[permission] = {
        effect: 'deny',
        source: `grant:${denyingGrant.id}`,
        reason: 'explicit_deny',
      };

      continue;
    }


    // -----------------------------------------------------------------------
    // Role baseline.
    // -----------------------------------------------------------------------

    if (baseline.has(permission)) {
      permissions[permission] = {
        effect: 'allow',
        source: `role:${state.membership.role}`,
        reason: null,
      };

      continue;
    }


    // -----------------------------------------------------------------------
    // Explicit allow grant.
    // -----------------------------------------------------------------------

    const allowingGrant = applicable.find(
      (grant) => grant.effect === 'allow'
    );

    if (allowingGrant) {
      permissions[permission] = {
        effect: 'allow',
        source: `grant:${allowingGrant.id}`,
        reason: null,
      };

      continue;
    }


    // -----------------------------------------------------------------------
    // D4 — nobody granted it -> implicit deny.
    // -----------------------------------------------------------------------

    permissions[permission] = {
      effect: 'deny',
      source: null,
      reason: 'implicit',
    };
  }

  return permissions;
}


// -----------------------------------------------------------------------------
// Main resolver
// -----------------------------------------------------------------------------

export function resolve(
  db,
  {
    userId,
    orgId,
    deviceId = null,
    now = new Date(),
  }
) {
  const state = loadState(db, { userId, orgId });

  // No membership -> everything denied.
  if (!state.membership) {
    return {
      role: null,
      permissions: emptyPermissionSet(
        state.catalogue,
        'not_a_member'
      ),
    };
  }


  // Suspended users have no authority.
  if (state.membership.status === 'suspended') {
    return {
      role: state.membership.role,
      permissions: emptyPermissionSet(
        state.catalogue,
        'suspended'
      ),
    };
  }


  // Invited / removed memberships are not active membership.
  if (state.membership.status !== 'active') {
    return {
      role: state.membership.role,
      permissions: emptyPermissionSet(
        state.catalogue,
        'not_a_member'
      ),
    };
  }


  const nowIso = now.toISOString();


  // -------------------------------------------------------------------------
  // Exact device-level question.
  // -------------------------------------------------------------------------

  if (deviceId !== null) {
    return {
      role: state.membership.role,
      permissions: resolveExact(
        state,
        deviceId,
        nowIso
      ),
    };
  }


  // -------------------------------------------------------------------------
  // Org-level view.
  //
  // The specification defines this as the UNION across devices.
  //
  // First resolve the role + org-wide grants. Then, if something is not
  // allowed there, see whether it is allowed on at least one actual device.
  //
  // An ORG-WIDE explicit deny is still final and cannot be carved out by a
  // device-specific allow.
  // -------------------------------------------------------------------------

  const orgPermissions = resolveExact(
    state,
    null,
    nowIso
  );

  const devices = db.prepare(`
    SELECT id
    FROM devices
    WHERE org_id = ?
      AND deleted_at IS NULL
  `).all(orgId);


  for (const permissionRow of state.catalogue) {
    const permission = permissionRow.key;

    // An org-wide explicit deny wins everywhere.
    if (
      orgPermissions[permission].reason ===
      'explicit_deny'
    ) {
      continue;
    }

    // Already allowed from role baseline or org-wide allow.
    if (
      orgPermissions[permission].effect === 'allow'
    ) {
      continue;
    }


    let firstExplicitDeny = null;
    let firstAllow = null;

    for (const device of devices) {
      const resolved = resolveExact(
        state,
        device.id,
        nowIso
      )[permission];

      if (resolved.effect === 'allow') {
        firstAllow = resolved;
        break;
      }

      if (
        !firstExplicitDeny &&
        resolved.reason === 'explicit_deny'
      ) {
        firstExplicitDeny = resolved;
      }
    }


    // Union semantics:
    // allowed somewhere -> allowed at org level.
    if (firstAllow) {
      orgPermissions[permission] = firstAllow;
    } else if (firstExplicitDeny) {
      orgPermissions[permission] = firstExplicitDeny;
    }
  }


  return {
    role: state.membership.role,
    permissions: orgPermissions,
  };
}


// -----------------------------------------------------------------------------
// Batched per-device resolver
// -----------------------------------------------------------------------------

export function resolveDevices(
  db,
  {
    userId,
    orgId,
    deviceIds,
    now = new Date(),
  }
) {
  const state = loadState(db, { userId, orgId });

  const byDevice = {};


  if (!state.membership) {
    for (const deviceId of deviceIds) {
      byDevice[deviceId] = emptyPermissionSet(
        state.catalogue,
        'not_a_member'
      );
    }

    return {
      role: null,
      byDevice,
    };
  }


  if (state.membership.status === 'suspended') {
    for (const deviceId of deviceIds) {
      byDevice[deviceId] = emptyPermissionSet(
        state.catalogue,
        'suspended'
      );
    }

    return {
      role: state.membership.role,
      byDevice,
    };
  }


  if (state.membership.status !== 'active') {
    for (const deviceId of deviceIds) {
      byDevice[deviceId] = emptyPermissionSet(
        state.catalogue,
        'not_a_member'
      );
    }

    return {
      role: state.membership.role,
      byDevice,
    };
  }


  const nowIso = now.toISOString();

  // Important:
  // loadState() happened ONCE.
  //
  // We are not issuing DB queries for every device row.
  for (const deviceId of deviceIds) {
    byDevice[deviceId] = resolveExact(
      state,
      deviceId,
      nowIso
    );
  }


  return {
    role: state.membership.role,
    byDevice,
  };
}


// -----------------------------------------------------------------------------
// Convenience checks
// -----------------------------------------------------------------------------

export function can(
  db,
  ctx,
  permission,
  deviceId = null
) {
  const result = resolve(db, {
    userId: ctx.userId,
    orgId: ctx.orgId,
    deviceId,
  });

  return (
    result.permissions[permission]?.effect ===
    'allow'
  );
}


export function assertCan(
  db,
  ctx,
  permission,
  deviceId = null
) {
  const result = resolve(db, {
    userId: ctx.userId,
    orgId: ctx.orgId,
    deviceId,
  });

  const resolved = result.permissions[permission];

  if (resolved?.effect === 'allow') {
    return resolved;
  }


  if (resolved?.reason === 'explicit_deny') {
    throw forbidden(
      `permission denied: ${permission}`,
      'explicit_deny'
    );
  }


  throw forbidden(
    `missing permission: ${permission}`,
    'missing_permission'
  );
}


// -----------------------------------------------------------------------------
// Grant safety — no privilege laundering
// -----------------------------------------------------------------------------

export function assertMayGrant(
  db,
  ctx,
  patterns,
  deviceId = null
) {
  const catalogue = db.prepare(`
    SELECT key
    FROM permissions
    ORDER BY key
  `).all().map((row) => row.key);


  // Convert wildcard patterns into concrete permissions.
  const required = new Set();

  for (const pattern of patterns) {
    const matching = catalogue.filter((permission) =>
      patternMatches(pattern, permission)
    );

    if (matching.length === 0) {
      throw badRequest(
        `unknown permission pattern: ${pattern}`
      );
    }

    for (const permission of matching) {
      required.add(permission);
    }
  }


  // Device-scoped grant:
  // creator must hold the authority on THAT device.
  if (deviceId !== null) {
    for (const permission of required) {
      if (!can(db, ctx, permission, deviceId)) {
        throw forbidden(
          `cannot grant permission you do not hold: ${permission}`,
          'scope_mismatch'
        );
      }
    }

    return;
  }


  // Org-wide grant:
  //
  // It could affect every device, so checking only one device would allow
  // authority to be "laundered" across scope.
  //
  // Therefore the caller must hold each permission at org scope and,
  // where devices exist, on every device.
  const devices = db.prepare(`
    SELECT id
    FROM devices
    WHERE org_id = ?
      AND deleted_at IS NULL
  `).all(ctx.orgId);


  for (const permission of required) {
    // First make sure it is available at org level.
    if (!can(db, ctx, permission, null)) {
      throw forbidden(
        `cannot grant permission you do not hold: ${permission}`,
        'scope_mismatch'
      );
    }


    // Ensure an org-wide grant cannot bypass a device-specific deny.
    for (const device of devices) {
      if (!can(db, ctx, permission, device.id)) {
        throw forbidden(
          `cannot grant permission you do not hold at every device scope: ${permission}`,
          'scope_mismatch'
        );
      }
    }
  }
}


// -----------------------------------------------------------------------------
// Session compound permission check
// -----------------------------------------------------------------------------

export function assertCanStartSession(
  db,
  ctx,
  mode,
  deviceId
) {
  const modePermission = MODE_PERMISSION[mode];

  if (!modePermission) {
    throw badRequest(`invalid session mode: ${mode}`);
  }


  // First permission:
  // session:start
  //
  // The API needs this failure reason to be distinguishable.
  if (!can(db, ctx, 'session:start', deviceId)) {
    throw forbidden(
      'missing session:start permission',
      'missing_permission'
    );
  }


  // Second permission:
  // device:view / device:control / device:terminal
  if (!can(db, ctx, modePermission, deviceId)) {
    throw forbidden(
      `missing device permission: ${modePermission}`,
      'missing_device_permission'
    );
  }
}