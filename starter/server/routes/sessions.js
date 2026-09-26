import {
  send,
  notFound,
  deviceBusy,
} from '../http.js';

import {
  assertCan,
  assertCanStartSession,
} from '../permissions.js';

import { newId } from '../db.js';


// -----------------------------------------------------------------------------
// POST /v1/orgs/:org/sessions
// -----------------------------------------------------------------------------

function createSession({ db }) {
  return async function createSessionHandler(ctx, params, res) {
    const { deviceId, mode } = ctx.body;

    const device = db.prepare(`
      SELECT id, org_id, deleted_at
      FROM devices
      WHERE id = ?
        AND org_id = ?
        AND deleted_at IS NULL
      LIMIT 1
    `).get(deviceId, ctx.orgId);

    if (!device) {
      throw notFound();
    }

    // Checks session:start + mode-specific device permission.
    assertCanStartSession(
      db,
      ctx,
      mode,
      deviceId
    );

    const org = db.prepare(`
      SELECT max_session_minutes
      FROM organizations
      WHERE id = ?
        AND deleted_at IS NULL
      LIMIT 1
    `).get(ctx.orgId);

    if (!org) {
      throw notFound();
    }

    const startedAt = new Date();
    const expiresAt = new Date(
      startedAt.getTime() +
      org.max_session_minutes * 60_000
    );

    const id = newId('ses');

    const authorizedBy = JSON.stringify({
      role: ctx.role,
      snapshotAt: startedAt.toISOString(),
    });

    try {
      db.prepare(`
        INSERT INTO sessions (
          id,
          org_id,
          user_id,
          device_id,
          mode,
          state,
          authorized_by,
          started_at,
          expires_at
        )
        VALUES (?, ?, ?, ?, ?, 'active', ?, ?, ?)
      `).run(
        id,
        ctx.orgId,
        ctx.userId,
        deviceId,
        mode,
        authorizedBy,
        startedAt.toISOString(),
        expiresAt.toISOString()
      );
    } catch (err) {
      // The DB unique index enforces exclusive control/terminal sessions.
      if (
        String(err?.message ?? '').includes(
          'UNIQUE constraint failed'
        )
      ) {
        throw deviceBusy();
      }

      throw err;
    }

    const session = db.prepare(`
      SELECT *
      FROM sessions
      WHERE id = ?
    `).get(id);

    send(res, 201, session);
  };
}


// -----------------------------------------------------------------------------
// GET /v1/orgs/:org/sessions
// -----------------------------------------------------------------------------

function listSessions({ db }) {
  return async function listSessionsHandler(ctx, params, res) {
    assertCan(db, ctx, 'session:view');

    const sessions = db.prepare(`
      SELECT *
      FROM sessions
      WHERE org_id = ?
      ORDER BY started_at DESC
    `).all(ctx.orgId);

    send(res, 200, { sessions });
  };
}


// -----------------------------------------------------------------------------
// GET /v1/sessions/:id
// -----------------------------------------------------------------------------

function getSession({ db }) {
  return async function getSessionHandler(ctx, params, res) {
    const session = db.prepare(`
      SELECT *
      FROM sessions
      WHERE id = ?
      LIMIT 1
    `).get(params.id);

    if (!session) {
      throw notFound();
    }

    // Structural org isolation.
    if (session.org_id !== ctx.orgId) {
      throw notFound();
    }

    // Participant can read their own session.
    if (session.user_id !== ctx.userId) {
      assertCan(
        db,
        ctx,
        'session:view',
        session.device_id
      );
    }

    send(res, 200, session);
  };
}


// -----------------------------------------------------------------------------
// Registration
// -----------------------------------------------------------------------------

export function registerSessionRoutes(router, deps) {
  router.post(
    '/v1/orgs/:org/sessions',
    createSession(deps)
  );

  router.get(
    '/v1/orgs/:org/sessions',
    listSessions(deps)
  );

  router.get(
    '/v1/sessions/:id',
    getSession(deps)
  );
}