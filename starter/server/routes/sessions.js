import {
  send,
  notFound,
  forbidden,
  conflict,
  deviceBusy,
} from '../http.js';

import {
  assertCan,
  assertCanStartSession,
} from '../permissions.js';

import {
  audit,
  auditDenials,
} from '../audit.js';

import {
  newId,
} from '../db.js';


// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

function loadSession(db, id) {
  return db.prepare(`
    SELECT *
    FROM sessions
    WHERE id = ?
    LIMIT 1
  `).get(id);
}


function ensureSameOrg(ctx, session) {
  if (!session || session.org_id !== ctx.orgId) {
    throw notFound();
  }
}


// -----------------------------------------------------------------------------
// POST /v1/orgs/:org/sessions
// -----------------------------------------------------------------------------

function createSession({ db }) {
  return async function createSessionHandler(ctx, params, res) {
    const {
      deviceId,
      mode,
    } = ctx.body;


    const device = db.prepare(`
      SELECT
        id,
        org_id,
        deleted_at
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


    return auditDenials(
      db,
      ctx,
      {
        action: 'session:start',
        targetType: 'device',
        targetId: deviceId,
      },
      () => {
        // Checks:
        // - session:start
        // - mode-specific device permission
        assertCanStartSession(
          db,
          ctx,
          mode,
          deviceId
        );


        const org = db.prepare(`
          SELECT
            max_session_minutes
          FROM organizations
          WHERE id = ?
            AND deleted_at IS NULL
          LIMIT 1
        `).get(
          ctx.orgId
        );


        if (!org) {
          throw notFound();
        }


        const startedAt =
          new Date();

        const expiresAt =
          new Date(
            startedAt.getTime() +
            org.max_session_minutes * 60_000
          );


        const id =
          newId('ses');


        const authorizedBy =
          JSON.stringify({
            role: ctx.role,
            deviceId,
            mode,
            snapshotAt:
              startedAt.toISOString(),
          });


        try {
          const tx =
            db.transaction(() => {
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
                VALUES (
                  ?, ?, ?, ?, ?,
                  'active',
                  ?, ?, ?
                )
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


              audit(
                db,
                {
                  orgId: ctx.orgId,
                  actorId: ctx.userId,
                  action: 'session:start',
                  targetType: 'session',
                  targetId: id,
                  result: 'allow',
                  reasonCode: null,
                  requestId:
                    ctx.requestId,
                }
              );
            });


          tx();

        } catch (err) {
          // Exclusive control/terminal sessions are
          // enforced by the database unique index.
          if (
            String(
              err?.message ?? ''
            ).includes(
              'UNIQUE constraint failed'
            )
          ) {
            throw deviceBusy();
          }

          throw err;
        }


        const session =
          loadSession(
            db,
            id
          );


        send(
          res,
          201,
          session
        );
      }
    );
  };
}


// -----------------------------------------------------------------------------
// GET /v1/orgs/:org/sessions
// -----------------------------------------------------------------------------

function listSessions({ db }) {
  return async function listSessionsHandler(
    ctx,
    params,
    res
  ) {
    assertCan(
      db,
      ctx,
      'session:view'
    );


    const sessions =
      db.prepare(`
        SELECT *
        FROM sessions
        WHERE org_id = ?
        ORDER BY started_at DESC
      `).all(
        ctx.orgId
      );


    send(
      res,
      200,
      {
        sessions,
      }
    );
  };
}


// -----------------------------------------------------------------------------
// GET /v1/sessions/:id
// -----------------------------------------------------------------------------

function getSession({ db }) {
  return async function getSessionHandler(
    ctx,
    params,
    res
  ) {
    const session =
      loadSession(
        db,
        params.id
      );


    ensureSameOrg(
      ctx,
      session
    );


    // A participant may view their own session.
    // Someone else needs session:view.
    if (
      session.user_id !==
      ctx.userId
    ) {
      assertCan(
        db,
        ctx,
        'session:view',
        session.device_id
      );
    }


    send(
      res,
      200,
      session
    );
  };
}


// -----------------------------------------------------------------------------
// DELETE /v1/sessions/:id
// -----------------------------------------------------------------------------

function terminateSession({ db }) {
  return async function terminateSessionHandler(
    ctx,
    params,
    res
  ) {
    const session =
      loadSession(
        db,
        params.id
      );


    ensureSameOrg(
      ctx,
      session
    );


    if (
      session.state !== 'active'
    ) {
      throw conflict(
        'session is not active'
      );
    }


    return auditDenials(
      db,
      ctx,
      {
        action: 'session:terminate',
        targetType: 'session',
        targetId: session.id,
      },
      () => {
        const ownSession =
          session.user_id ===
          ctx.userId;


        // A user may always stop their OWN session.
        // Stopping another person's session requires
        // session:terminate.
        if (!ownSession) {
          assertCan(
            db,
            ctx,
            'session:terminate',
            session.device_id
          );
        }


        const now =
          new Date().toISOString();


        const reason =
          ownSession
            ? 'user_stopped'
            : 'admin_terminated';


        const tx =
          db.transaction(() => {
            const result =
              db.prepare(`
                UPDATE sessions
                SET
                  state = 'ended',
                  ended_at = ?,
                  end_reason = ?
                WHERE id = ?
                  AND state = 'active'
              `).run(
                now,
                reason,
                session.id
              );


            if (
              result.changes !== 1
            ) {
              throw conflict(
                'session is not active'
              );
            }


            audit(
              db,
              {
                orgId:
                  ctx.orgId,

                actorId:
                  ctx.userId,

                action:
                  'session:terminate',

                targetType:
                  'session',

                targetId:
                  session.id,

                result:
                  'allow',

                reasonCode:
                  reason,

                requestId:
                  ctx.requestId,
              }
            );
          });


        tx();


        const updated =
          loadSession(
            db,
            session.id
          );


        send(
          res,
          200,
          updated
        );
      }
    );
  };
}


// -----------------------------------------------------------------------------
// Registration
// -----------------------------------------------------------------------------

export function registerSessionRoutes(
  router,
  deps
) {
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

  router.delete(
    '/v1/sessions/:id',
    terminateSession(deps)
  );
}