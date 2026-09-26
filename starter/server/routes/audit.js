import { send, badRequest } from '../http.js';
import { assertCan } from '../permissions.js';

export function registerAuditRoutes(router, { db }) {
  router.get('/v1/orgs/:org/audit', async (ctx, params, res) => {
    assertCan(db, ctx, 'audit:read');

    const rawLimit = ctx.query.get('limit');
    const rawOffset = ctx.query.get('offset');

    const limit = rawLimit === null ? 50 : Number(rawLimit);
    const offset = rawOffset === null ? 0 : Number(rawOffset);

    if (
      !Number.isInteger(limit) ||
      limit <= 0 ||
      limit > 200
    ) {
      throw badRequest('limit must be between 1 and 200');
    }

    if (
      !Number.isInteger(offset) ||
      offset < 0
    ) {
      throw badRequest('offset must be zero or greater');
    }

    const events = db.prepare(`
      SELECT
        id,
        org_id,
        actor_id,
        action,
        target_type,
        target_id,
        result,
        reason_code,
        request_id,
        at
      FROM audit_events
      WHERE org_id = ?
      ORDER BY at DESC
      LIMIT ? OFFSET ?
    `).all(ctx.orgId, limit, offset);

    send(res, 200, { events });
  });
}