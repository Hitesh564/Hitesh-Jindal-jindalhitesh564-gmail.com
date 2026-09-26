import {
  send,
  badRequest,
  notFound,
  conflict,
  forbidden,
  gone,
} from '../http.js';

import {
  newId,
} from '../db.js';

import {
  newInviteToken,
  hashInviteToken,
  hashPassword,
  issueAccessToken,
} from '../auth.js';

import {
  assertCan,
} from '../permissions.js';

import {
  assertRoleExists,
  roleRanks,
} from '../lifecycle.js';


import {
  audit,
  auditDenials,
} from '../audit.js';

const INVITE_TTL_MS =
  7 * 24 * 60 * 60 * 1000;


// -----------------------------------------------------------------------------
// POST /v1/orgs/:org/invites
// -----------------------------------------------------------------------------

function createInvite({ db }) {
  return async function handler(ctx, params, res) {
    return auditDenials(
      db,
      ctx,
      {
        action: 'user:invite',
        targetType: 'invite',
        targetId: null,
      },
      () => {
        assertCan(db, ctx, 'user:invite');

        const email =
          typeof ctx.body.email === 'string'
            ? ctx.body.email.trim().toLowerCase()
            : '';

        const role =
          typeof ctx.body.role === 'string'
            ? ctx.body.role
            : '';


        if (!email) {
          throw badRequest('email is required');
        }

        assertRoleExists(db, role);


        // Role assignment authority.
        const ranks = roleRanks(db);

        if (role === 'owner' && ctx.role !== 'owner') {
          throw forbidden(
            'only an owner may assign owner'
          );
        }

        if (
          ctx.role !== 'owner' &&
          ranks[role] >= ranks[ctx.role]
        ) {
          throw forbidden(
            'cannot assign this role'
          );
        }


    const existingUser = db.prepare(`
      SELECT id
      FROM users
      WHERE email = ?
      LIMIT 1
    `).get(email);


    if (existingUser) {
      const membership = db.prepare(`
        SELECT status
        FROM memberships
        WHERE org_id = ?
          AND user_id = ?
        LIMIT 1
      `).get(
        ctx.orgId,
        existingUser.id
      );

      if (
        membership &&
        membership.status === 'active'
      ) {
        throw conflict(
          'user is already a member'
        );
      }
    }


    const existingInvite = db.prepare(`
      SELECT id
      FROM invites
      WHERE org_id = ?
        AND email = ?
        AND accepted_at IS NULL
        AND revoked_at IS NULL
      LIMIT 1
    `).get(
      ctx.orgId,
      email
    );

    if (existingInvite) {
      throw conflict(
        'a live invite already exists'
      );
    }


    const rawToken = newInviteToken();

    const id = newId('inv');

    const expiresAt = new Date(
      Date.now() + INVITE_TTL_MS
    ).toISOString();


    const tx = db.transaction(() => {
      db.prepare(`
        INSERT INTO invites (
          id,
          org_id,
          email,
          role,
          token_hash,
          invited_by,
          expires_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
      `).run(
        id,
        ctx.orgId,
        email,
        role,
        hashInviteToken(rawToken),
        ctx.userId,
        expiresAt
      );

      audit(db, {
        orgId: ctx.orgId,
        actorId: ctx.userId,
        action: 'user:invite',
        targetType: 'invite',
        targetId: id,
        result: 'allow',
        reasonCode: role,
        requestId: ctx.requestId,
      });
    });

    tx();

        send(res, 201, {
          id,
          email,
          role,
          expiresAt,

          // Raw bearer credential returned once.
          inviteToken: rawToken,
        });
      }
    );
  };
}


// -----------------------------------------------------------------------------
// GET /v1/invites/:token
// PUBLIC
// -----------------------------------------------------------------------------

function peekInvite({ db }) {
  return async function handler(ctx, params, res) {
    const invite = db.prepare(`
      SELECT
        i.id,
        i.email,
        i.role,
        i.expires_at,
        i.accepted_at,
        i.revoked_at,
        o.name AS org_name
      FROM invites i
      JOIN organizations o
        ON o.id = i.org_id
      WHERE i.token_hash = ?
      LIMIT 1
    `).get(
      hashInviteToken(params.token)
    );


    if (!invite) {
      throw notFound();
    }


    if (
      invite.revoked_at ||
      (
        !invite.accepted_at &&
        invite.expires_at <=
          new Date().toISOString()
      )
    ) {
      throw gone();
    }


    if (invite.accepted_at) {
      throw conflict(
        'invite has already been accepted'
      );
    }


    // Deliberately does NOT return org id,
    // devices, members, etc.
    send(res, 200, {
      orgName: invite.org_name,
      role: invite.role,
      email: invite.email,
      expiresAt: invite.expires_at,
    });
  };
}


// -----------------------------------------------------------------------------
// POST /v1/invites/:token/accept
// PUBLIC
// -----------------------------------------------------------------------------

function acceptInvite({ db, secret }) {
  return async function handler(ctx, params, res) {
    const tokenHash =
      hashInviteToken(params.token);


    const invite = db.prepare(`
      SELECT
        id,
        org_id,
        email,
        role,
        expires_at,
        accepted_at,
        revoked_at
      FROM invites
      WHERE token_hash = ?
      LIMIT 1
    `).get(tokenHash);


    if (!invite) {
      throw notFound();
    }


    if (invite.accepted_at) {
      throw conflict(
        'invite has already been accepted'
      );
    }


    if (
      invite.revoked_at ||
      invite.expires_at <=
        new Date().toISOString()
    ) {
      throw gone();
    }


    const name =
      typeof ctx.body.name === 'string'
        ? ctx.body.name.trim()
        : '';

    const password =
      typeof ctx.body.password === 'string'
        ? ctx.body.password
        : '';


    let user = db.prepare(`
      SELECT
        id,
        email,
        name
      FROM users
      WHERE email = ?
      LIMIT 1
    `).get(invite.email);


    // A brand-new platform user needs identity data.
    if (!user) {
      if (!name) {
        throw badRequest('name is required');
      }

      if (password.length < 8) {
        throw badRequest(
          'password must be at least 8 characters'
        );
      }
    }


    let membership;


    const tx = db.transaction(() => {
      if (!user) {
        const userId = newId('usr');

        db.prepare(`
          INSERT INTO users (
            id,
            email,
            name,
            password_hash
          )
          VALUES (?, ?, ?, ?)
        `).run(
          userId,
          invite.email,
          name,
          hashPassword(password)
        );

        user = {
          id: userId,
          email: invite.email,
          name,
        };
      }


      membership = db.prepare(`
        SELECT
          id,
          status
        FROM memberships
        WHERE org_id = ?
          AND user_id = ?
        LIMIT 1
      `).get(
        invite.org_id,
        user.id
      );


      if (membership) {
        if (membership.status === 'active') {
          throw conflict(
            'user is already a member'
          );
        }

        db.prepare(`
          UPDATE memberships
          SET
            role = ?,
            status = 'active',
            perm_version =
              perm_version + 1,
            joined_at = ?
          WHERE id = ?
        `).run(
          invite.role,
          new Date().toISOString(),
          membership.id
        );
      } else {
        const membershipId =
          newId('mem');

        db.prepare(`
          INSERT INTO memberships (
            id,
            org_id,
            user_id,
            role,
            status,
            joined_at
          )
          VALUES (
            ?, ?, ?, ?, 'active', ?
          )
        `).run(
          membershipId,
          invite.org_id,
          user.id,
          invite.role,
          new Date().toISOString()
        );
      }


      const result = db.prepare(`
        UPDATE invites
        SET
          accepted_at = ?,
          accepted_by = ?
        WHERE id = ?
          AND accepted_at IS NULL
          AND revoked_at IS NULL
      `).run(
        new Date().toISOString(),
        user.id,
        invite.id
      );


      // Handles a concurrent second acceptance.
      if (result.changes !== 1) {
        throw conflict(
          'invite has already been accepted'
        );
      }
    });

    tx();


    const activeMembership = db.prepare(`
      SELECT
        role,
        perm_version
      FROM memberships
      WHERE org_id = ?
        AND user_id = ?
        AND status = 'active'
    `).get(
      invite.org_id,
      user.id
    );


    const token = issueAccessToken(
      {
        userId: user.id,
        orgId: invite.org_id,
        role: activeMembership.role,
        permVersion:
          activeMembership.perm_version,
      },
      secret
    );


    send(res, 200, {
      token,
      role: activeMembership.role,

      user: {
        id: user.id,
        email: user.email,
        name: user.name,
      },
    });
  };
}


// -----------------------------------------------------------------------------
// GET org invites
// -----------------------------------------------------------------------------

function listInvites({ db }) {
  return async function handler(ctx, params, res) {
    assertCan(db, ctx, 'user:invite');

    const invites = db.prepare(`
      SELECT
        id,
        email,
        role,
        expires_at,
        accepted_at,
        revoked_at,
        created_at
      FROM invites
      WHERE org_id = ?
      ORDER BY created_at DESC
    `).all(ctx.orgId);

    send(res, 200, { invites });
  };
}


// -----------------------------------------------------------------------------
// Revoke invite
// -----------------------------------------------------------------------------

function revokeInvite({ db }) {
  return async function handler(ctx, params, res) {
    return auditDenials(
      db,
      ctx,
      {
        action: 'user:invite',
        targetType: 'invite',
        targetId: params.id,
      },
      () => {
        assertCan(db, ctx, 'user:invite');

        const invite = db.prepare(`
          SELECT id
          FROM invites
          WHERE id = ?
            AND org_id = ?
            AND accepted_at IS NULL
            AND revoked_at IS NULL
          LIMIT 1
        `).get(
          params.id,
          ctx.orgId
        );

        if (!invite) {
          throw notFound();
        }

        const tx = db.transaction(() => {
          db.prepare(`
            UPDATE invites
            SET revoked_at = ?
            WHERE id = ?
          `).run(
            new Date().toISOString(),
            invite.id
          );

          audit(db, {
            orgId: ctx.orgId,
            actorId: ctx.userId,
            action: 'user:invite',
            targetType: 'invite',
            targetId: invite.id,
            result: 'allow',
            reasonCode: 'revoked',
            requestId: ctx.requestId,
          });
        });

        tx();

        send(res, 200, {
          id: invite.id,
          revoked: true,
        });
      }
    );
  };
}


export function registerInviteRoutes(
  router,
  deps
) {
  router.post(
    '/v1/orgs/:org/invites',
    createInvite(deps)
  );

  router.get(
    '/v1/orgs/:org/invites',
    listInvites(deps)
  );

  router.delete(
    '/v1/orgs/:org/invites/:id',
    revokeInvite(deps)
  );

  router.get(
    '/v1/invites/:token',
    peekInvite(deps)
  );

  router.post(
    '/v1/invites/:token/accept',
    acceptInvite(deps)
  );
}