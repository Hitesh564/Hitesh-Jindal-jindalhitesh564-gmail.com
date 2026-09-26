import { newId } from './db.js';

export function audit(
  db,
  {
    orgId,
    actorId,
    action,
    targetType,
    targetId,
    result,
    reasonCode = null,
    requestId = null,
  }
) {
  const id = newId('aud');

  db.prepare(`
    INSERT INTO audit_events (
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
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    id,
    orgId,
    actorId ?? null,
    action,
    targetType ?? null,
    targetId ?? null,
    result,
    reasonCode,
    requestId,
    new Date().toISOString()
  );

  return id;
}

export function auditDenials(
  db,
  ctx,
  meta,
  fn
) {
  try {
    return fn();
  } catch (err) {
    const status =
      err?.status ??
      err?.statusCode;

    const isPermissionDenial =
      status === 403 ||
      err?.code === 'FORBIDDEN';

    if (isPermissionDenial) {
      audit(db, {
        orgId: ctx.orgId,
        actorId: ctx.userId,
        action: meta.action,
        targetType: meta.targetType,
        targetId: meta.targetId ?? null,
        result: 'deny',
        reasonCode:
          err?.reason ??
          err?.code ??
          'FORBIDDEN',
        requestId: ctx.requestId,
      });
    }

    throw err;
  }
}