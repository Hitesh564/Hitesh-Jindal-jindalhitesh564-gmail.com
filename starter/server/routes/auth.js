
import {
  issueAccessToken,
  verifyPassword,
  newRefreshToken,
  hashRefreshToken,
  REFRESH_TTL_SECONDS,
} from '../auth.js';

import { newId } from '../db.js';
function setRefreshCookie(res, rawToken) {
  res.setHeader(
    'Set-Cookie',
    [
      `rt=${rawToken}`,
      'HttpOnly',
      'SameSite=Strict',
      'Path=/v1/auth/refresh',
      `Max-Age=${REFRESH_TTL_SECONDS}`,
      'Secure',
    ].join('; ')
  );
}

function readCookie(req, name) {
  const raw = req.headers.cookie ?? '';

  for (const part of raw.split(';')) {
    const [key, ...rest] = part.trim().split('=');

    if (key === name) {
      return rest.join('=');
    }
  }

  return null;
}

function createRefreshSession(db, userId) {
  const rawToken = newRefreshToken();

  const familyId = newId('rfam');
  const id = newId('rft');

  const expiresAt = new Date(
    Date.now() + REFRESH_TTL_SECONDS * 1000
  ).toISOString();

  db.prepare(`
    INSERT INTO refresh_tokens (
      id,
      user_id,
      token_hash,
      family_id,
      expires_at
    )
    VALUES (?, ?, ?, ?, ?)
  `).run(
    id,
    userId,
    hashRefreshToken(rawToken),
    familyId,
    expiresAt
  );

  return {
    rawToken,
    familyId,
    expiresAt,
  };
}

import { resolve } from '../permissions.js';

import {
  unauthenticated,
  notFound,
  send,
} from '../http.js';


// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

function getActiveMemberships(db, userId) {
  return db.prepare(`
    SELECT
      m.id,
      m.org_id,
      m.user_id,
      m.role,
      m.status,
      m.perm_version,
      m.joined_at,
      o.name AS org_name,
      o.theme AS org_theme
    FROM memberships m
    JOIN organizations o
      ON o.id = m.org_id
    WHERE m.user_id = ?
      AND m.status = 'active'
      AND o.deleted_at IS NULL
    ORDER BY m.joined_at ASC, o.name ASC
  `).all(userId);
}


function publicOrgShape(membership) {
  return {
    id: membership.org_id,
    name: membership.org_name,
    theme: membership.org_theme,
    role: membership.role,
  };
}


// -----------------------------------------------------------------------------
// POST /v1/auth/login
// -----------------------------------------------------------------------------

function login({ db, secret }) {
  return async function loginHandler(ctx, params, res) {
    const email =
      typeof ctx.body.email === 'string'
        ? ctx.body.email.trim().toLowerCase()
        : '';

    const password =
      typeof ctx.body.password === 'string'
        ? ctx.body.password
        : '';

    const requestedOrgId =
      typeof ctx.body.orgId === 'string'
        ? ctx.body.orgId
        : null;


    // Do not reveal whether the email exists.
    if (!email || !password) {
      throw unauthenticated('invalid email or password');
    }


    const user = db.prepare(`
      SELECT
        id,
        email,
        name,
        password_hash
      FROM users
      WHERE email = ?
      LIMIT 1
    `).get(email);


    // Same response for:
    // - unknown email
    // - wrong password
    //
    // This avoids an account-enumeration leak.
    if (
      !user ||
      !verifyPassword(password, user.password_hash)
    ) {
      throw unauthenticated('invalid email or password');
    }


    const memberships = getActiveMemberships(db, user.id);

    if (memberships.length === 0) {
      throw unauthenticated('no active organization membership');
    }


    // If the caller explicitly requested an org, use that membership.
    // Otherwise use the first active membership.
    const activeMembership = requestedOrgId
      ? memberships.find(
          (membership) =>
            membership.org_id === requestedOrgId
        )
      : memberships[0];


    if (!activeMembership) {
      throw unauthenticated('invalid organization membership');
    }


    const token = issueAccessToken(
      {
        userId: user.id,
        orgId: activeMembership.org_id,
        role: activeMembership.role,
        permVersion: activeMembership.perm_version,
      },
      secret
    );

    const refresh = createRefreshSession(db, user.id);
    setRefreshCookie(res, refresh.rawToken);

    send(res, 200, {
      token,

      user: {
        id: user.id,
        email: user.email,
        name: user.name,
      },

      orgId: activeMembership.org_id,
      role: activeMembership.role,

      orgs: memberships.map(publicOrgShape),
    });
  };
}


// -----------------------------------------------------------------------------
// POST /v1/auth/token
//
// Switch organization. The current access token proves the user's identity.
// We then find an ACTIVE membership in the requested organization and issue
// another access token scoped only to that organization.
// -----------------------------------------------------------------------------

function switchOrg({ db, secret }) {
  return async function switchOrgHandler(ctx, params, res) {
    const orgId =
      typeof ctx.body.orgId === 'string'
        ? ctx.body.orgId
        : '';

    if (!orgId) {
      throw notFound();
    }


    const membership = db.prepare(`
      SELECT
        m.id,
        m.org_id,
        m.user_id,
        m.role,
        m.status,
        m.perm_version,
        o.name AS org_name,
        o.theme AS org_theme
      FROM memberships m
      JOIN organizations o
        ON o.id = m.org_id
      WHERE m.user_id = ?
        AND m.org_id = ?
        AND m.status = 'active'
        AND o.deleted_at IS NULL
      LIMIT 1
    `).get(ctx.userId, orgId);


    // Do not expose organizations the caller does not belong to.
    if (!membership) {
      throw notFound();
    }


    const token = issueAccessToken(
      {
        userId: ctx.userId,
        orgId: membership.org_id,
        role: membership.role,
        permVersion: membership.perm_version,
      },
      secret
    );


    send(res, 200, {
      token,
      orgId: membership.org_id,
      role: membership.role,

      org: {
        id: membership.org_id,
        name: membership.org_name,
        theme: membership.org_theme,
      },
    });
  };
}


// -----------------------------------------------------------------------------
// Registration
// -----------------------------------------------------------------------------
// -----------------------------------------------------------------------------
// GET /v1/auth/me
// -----------------------------------------------------------------------------

function me({ db }) {
  return async function meHandler(ctx, params, res) {
    const user = db.prepare(`
      SELECT id, email, name
      FROM users
      WHERE id = ?
      LIMIT 1
    `).get(ctx.userId);

    if (!user) {
      throw unauthenticated();
    }

    const memberships = getActiveMemberships(
      db,
      ctx.userId
    );

    const activeOrg = memberships.find(
      (membership) =>
        membership.org_id === ctx.orgId
    );

    if (!activeOrg) {
      throw unauthenticated(
        'no active organization membership'
      );
    }

    const resolved = resolve(db, {
      userId: ctx.userId,
      orgId: ctx.orgId,
    });

    send(res, 200, {
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
      },

      org: {
        id: activeOrg.org_id,
        name: activeOrg.org_name,
        theme: activeOrg.org_theme,
      },

      orgId: activeOrg.org_id,
      role: activeOrg.role,

      orgs: memberships.map(publicOrgShape),

      permissions: resolved.permissions,
    });
  };
}

function refresh({ db, secret }) {
  return async function refreshHandler(ctx, params, res) {
    const rawToken = readCookie(
      ctx.req,
      'rt'
    );

    if (!rawToken) {
      throw unauthenticated(
        'missing refresh token'
      );
    }

    const tokenHash =
      hashRefreshToken(rawToken);

    const stored = db.prepare(`
      SELECT
        id,
        user_id,
        family_id,
        expires_at,
        revoked_at
      FROM refresh_tokens
      WHERE token_hash = ?
      LIMIT 1
    `).get(tokenHash);

    if (!stored) {
      throw unauthenticated(
        'invalid refresh token'
      );
    }

    // A previously rotated/revoked token being reused
    // kills the whole family.
    if (stored.revoked_at) {
      db.prepare(`
        UPDATE refresh_tokens
        SET revoked_at = COALESCE(
          revoked_at,
          ?
        )
        WHERE family_id = ?
      `).run(
        new Date().toISOString(),
        stored.family_id
      );

      throw unauthenticated(
        'refresh token has been revoked'
      );
    }

    if (
      stored.expires_at <=
      new Date().toISOString()
    ) {
      throw unauthenticated(
        'refresh token expired'
      );
    }

    const memberships =
      getActiveMemberships(
        db,
        stored.user_id
      );

    if (memberships.length === 0) {
      throw unauthenticated(
        'no active organization membership'
      );
    }

    // With the current schema the refresh token is
    // user-scoped, not org-scoped, so restore the
    // first active membership.
    const membership = memberships[0];

    const nextRaw =
      newRefreshToken();

    const nextId =
      newId('rft');

    const nextExpiry = new Date(
      Date.now() +
      REFRESH_TTL_SECONDS * 1000
    ).toISOString();

    const now =
      new Date().toISOString();

    const rotate = db.transaction(() => {
      db.prepare(`
        UPDATE refresh_tokens
        SET revoked_at = ?
        WHERE id = ?
          AND revoked_at IS NULL
      `).run(
        now,
        stored.id
      );

      db.prepare(`
        INSERT INTO refresh_tokens (
          id,
          user_id,
          token_hash,
          family_id,
          expires_at
        )
        VALUES (?, ?, ?, ?, ?)
      `).run(
        nextId,
        stored.user_id,
        hashRefreshToken(nextRaw),
        stored.family_id,
        nextExpiry
      );
    });

    rotate();

    const accessToken =
      issueAccessToken(
        {
          userId: stored.user_id,
          orgId: membership.org_id,
          role: membership.role,
          permVersion:
            membership.perm_version,
        },
        secret
      );

    setRefreshCookie(
      res,
      nextRaw
    );

    send(res, 200, {
      token: accessToken,
      orgId: membership.org_id,
      role: membership.role,
    });
  };
}

export function registerAuthRoutes(router, deps) {
  router.post(
    '/v1/auth/login',
    login(deps)
  );

  router.post(
    '/v1/auth/refresh',
    refresh(deps)
  );

  router.post(
    '/v1/auth/token',
    switchOrg(deps)
  );

  router.get(
    '/v1/auth/me',
    me(deps)
  );
}