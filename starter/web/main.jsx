import React, { useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';

const API = '/v1';

const THEMES = {
  cobalt: '#eaf1ff',
  amber: '#fff4d6',
};

function hasPermission(permissions, key) {
  return permissions?.[key]?.effect === 'allow';
}

async function request(path, { token, method = 'GET', body } = {}) {
  const headers = {};

  if (token) {
    headers.authorization = `Bearer ${token}`;
  }

  if (body !== undefined) {
    headers['content-type'] = 'application/json';
  }

  const response = await fetch(`${API}${path}`, {
    method,
    headers,
    credentials: 'include',
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });

  let data = null;

  try {
    data = await response.json();
  } catch {
    // ignore empty/non-json body
  }

  if (!response.ok) {
    const error = new Error(
      data?.error?.message || `Request failed (${response.status})`
    );

    error.status = response.status;
    error.code = data?.error?.code;
    error.reason = data?.error?.reason;

    throw error;
  }

  return data;
}

function Login({ onLogin }) {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState(null);

  async function submit(event) {
    event.preventDefault();
    setError(null);

    if (!email.trim() || !password) {
      setError({
        code: 'VALIDATION',
        message: 'Email and password are required.',
      });
      return;
    }

    try {
      const result = await request('/auth/login', {
        method: 'POST',
        body: {
          email: email.trim(),
          password,
        },
      });

      await onLogin(result.token);
    } catch (err) {
      setError({
        code: err.code || 'UNAUTHENTICATED',
        message: err.message,
      });
    }
  }

  return (
    <main style={styles.loginPage}>
      <form
        data-testid="login-form"
        onSubmit={submit}
        style={styles.loginCard}
      >
        <h1>RemoteOps</h1>
        <p>Sign in to your organization console.</p>

        <label>
          Email
          <input
            data-testid="login-email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            style={styles.input}
          />
        </label>

        <label>
          Password
          <input
            data-testid="login-password"
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            style={styles.input}
          />
        </label>

        <button
          data-testid="login-submit"
          type="submit"
          style={styles.primaryButton}
        >
          Sign in
        </button>

        {error && (
          <div
            data-testid="login-error"
            data-error-code={error.code}
            role="alert"
            style={styles.error}
          >
            {error.message}
          </div>
        )}
      </form>
    </main>
  );
}

function InvitePage({ inviteToken, onFinished }) {
  const [invite, setInvite] = useState(null);
  const [error, setError] = useState(null);
  const [name, setName] = useState('');
  const [password, setPassword] = useState('');

  useEffect(() => {
    request(`/invites/${inviteToken}`)
      .then(setInvite)
      .catch((err) => setError(err.message));
  }, [inviteToken]);

  async function accept(event) {
    event.preventDefault();

    try {
      await request(`/invites/${inviteToken}/accept`, {
        method: 'POST',
        body: { name, password },
      });

      onFinished();
    } catch (err) {
      setError(err.message);
    }
  }

  if (error) {
    return (
      <main style={styles.loginPage}>
        <div data-testid="invite-error" role="alert" style={styles.error}>
          {error}
        </div>
      </main>
    );
  }

  if (!invite) {
    return <main style={styles.loginPage}>Loading invite…</main>;
  }

  return (
    <main style={styles.loginPage}>
      <form onSubmit={accept} style={styles.loginCard}>
        <h1>Accept invitation</h1>

        <p>
          Role: <strong data-testid="invite-role">{invite.role}</strong>
        </p>

        <input
          data-testid="invite-email"
          value={invite.email}
          readOnly
          style={styles.input}
        />

        <input
          data-testid="invite-name"
          placeholder="Your name"
          value={name}
          onChange={(e) => setName(e.target.value)}
          style={styles.input}
        />

        <input
          data-testid="invite-password"
          type="password"
          placeholder="Choose a password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          style={styles.input}
        />

        <button
          data-testid="invite-submit"
          type="submit"
          style={styles.primaryButton}
        >
          Join organization
        </button>
      </form>
    </main>
  );
}

function Devices({ token, me }) {
  const [devices, setDevices] = useState([]);
  const [loaded, setLoaded] = useState(false);

  async function load() {
    setLoaded(false);

    const data = await request(
      `/orgs/${me.orgId}/devices`,
      { token }
    );

    setDevices(data.devices);
    setLoaded(true);
  }

  useEffect(() => {
    load();
  }, [token, me.orgId]);

  if (loaded && devices.length === 0) {
    return <p data-testid="devices-empty">No devices yet.</p>;
  }

  return (
    <div>
      <h2>Devices</h2>

      <table>
        <tbody>
          {devices.map((device) => {
            const p = device.permissions;

            return (
              <tr
                key={device.id}
                data-testid="device-row"
                data-device-id={device.id}
              >
                <td>{device.name}</td>
                <td>{device.kind}</td>

                <td>
                  {hasPermission(p, 'device:view') && (
                    <button
                      data-testid="start-view"
                      data-permission="device:view"
                      data-state="unlocked"
                    >
                      View
                    </button>
                  )}

                  {hasPermission(p, 'device:control') && (
                    <button
                      data-testid="start-control"
                      data-permission="device:control"
                      data-state="unlocked"
                    >
                      Control
                    </button>
                  )}

                  {hasPermission(p, 'device:terminal') && (
                    <button
                      data-testid="start-terminal"
                      data-permission="device:terminal"
                      data-state="unlocked"
                    >
                      Terminal
                    </button>
                  )}

                  {hasPermission(p, 'device:file_transfer') && (
                    <button
                      data-testid="transfer-files"
                      data-permission="device:file_transfer"
                      data-state="unlocked"
                    >
                      Transfer files
                    </button>
                  )}

                  {hasPermission(p, 'device:update') && (
                    <button
                      data-testid="rename-device"
                      data-permission="device:update"
                      data-state="unlocked"
                    >
                      Rename
                    </button>
                  )}

                  {hasPermission(p, 'device:provision') && (
                    <button
                      data-testid="decommission-device"
                      data-permission="device:provision"
                      data-state="unlocked"
                    >
                      Decommission
                    </button>
                  )}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>

      {hasPermission(me.permissions, 'device:provision') && (
        <button
          data-testid="add-device"
          data-permission="device:provision"
          data-state="unlocked"
        >
          Add device
        </button>
      )}
    </div>
  );
}

function People({ token, me }) {
  const [members, setMembers] = useState([]);

  useEffect(() => {
    request(`/orgs/${me.orgId}/members`, { token })
      .then((data) => setMembers(data.members));
  }, [token, me.orgId]);

  return (
    <div>
      <h2>People</h2>

      {hasPermission(me.permissions, 'user:invite') && (
        <button
          data-testid="invite-user"
          data-permission="user:invite"
          data-state="unlocked"
        >
          Invite user
        </button>
      )}

      <table>
        <tbody>
          {members.map((member) => (
            <tr
              key={member.id}
              data-testid="user-row"
              data-user-id={member.id}
            >
              <td>{member.name}</td>
              <td>{member.email}</td>
              <td>{member.role}</td>

              <td>
                {hasPermission(me.permissions, 'user:role:update') && (
                  <select
                    data-testid="role-select"
                    data-permission="user:role:update"
                    data-state="unlocked"
                    defaultValue={member.role}
                  >
                    <option>{member.role}</option>
                  </select>
                )}

                {hasPermission(me.permissions, 'user:remove') && (
                  <>
                    <button
                      data-testid="suspend-user"
                      data-permission="user:remove"
                      data-state="unlocked"
                    >
                      Suspend
                    </button>

                    <button
                      data-testid="remove-user"
                      data-permission="user:remove"
                      data-state="unlocked"
                    >
                      Remove
                    </button>
                  </>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function Grants({ token, me }) {
  const [grants, setGrants] = useState([]);
  const [members, setMembers] = useState([]);
  const [devices, setDevices] = useState([]);
  const [creating, setCreating] = useState(false);

  const [userId, setUserId] = useState('');
  const [deviceId, setDeviceId] = useState('');
  const [effect, setEffect] = useState('allow');
  const [selected, setSelected] = useState({});

  async function load() {
    const grantsData = await request(
      `/orgs/${me.orgId}/grants`,
      { token }
    );

    setGrants(grantsData.grants);

    if (hasPermission(me.permissions, 'grant:create')) {
      const [membersData, devicesData] = await Promise.all([
        request(`/orgs/${me.orgId}/members`, { token }),
        request(`/orgs/${me.orgId}/devices`, { token }),
      ]);

      setMembers(membersData.members);
      setDevices(devicesData.devices);
    }
  }

  useEffect(() => {
    load();
  }, [token, me.orgId]);

  async function submit(event) {
    event.preventDefault();

    const permissions = Object.entries(selected)
      .filter(([, checked]) => checked)
      .map(([key]) => key);

    await request(`/orgs/${me.orgId}/grants`, {
      token,
      method: 'POST',
      body: {
        userId,
        deviceId: deviceId || null,
        effect,
        permissions,
      },
    });

    setCreating(false);
    setSelected({});
    await load();
  }

  return (
    <div>
      <h2>Grants</h2>

      {hasPermission(me.permissions, 'grant:create') && (
        <button
          data-testid="new-grant"
          data-permission="grant:create"
          data-state="unlocked"
          onClick={() => setCreating(true)}
        >
          New grant
        </button>
      )}

      {creating && (
        <form onSubmit={submit}>
          <select
            data-testid="grant-user"
            value={userId}
            onChange={(e) => setUserId(e.target.value)}
          >
            <option value="">Select user</option>
            {members.map((member) => (
              <option key={member.id} value={member.id}>
                {member.name}
              </option>
            ))}
          </select>

          <select
            data-testid="grant-device"
            value={deviceId}
            onChange={(e) => setDeviceId(e.target.value)}
          >
            <option value="">Org wide</option>
            {devices.map((device) => (
              <option key={device.id} value={device.id}>
                {device.name}
              </option>
            ))}
          </select>

          <select
            data-testid="grant-effect"
            value={effect}
            onChange={(e) => setEffect(e.target.value)}
          >
            <option value="allow">Allow</option>
            <option value="deny">Deny</option>
          </select>

          {Object.keys(me.permissions).map((permission) => (
            <label key={permission} style={{ display: 'block' }}>
              <input
                type="checkbox"
                data-permission-key={permission}
                checked={Boolean(selected[permission])}
                onChange={(e) =>
                  setSelected((old) => ({
                    ...old,
                    [permission]: e.target.checked,
                  }))
                }
              />
              {permission}
            </label>
          ))}

          <button data-testid="grant-submit" type="submit">
            Create
          </button>
        </form>
      )}

      <table>
        <tbody>
          {grants.map((grant) => (
            <tr
              key={grant.id}
              data-testid="grant-row"
              data-effect={grant.effect}
            >
              <td>{grant.userId}</td>
              <td>{grant.effect}</td>
              <td>{grant.permissions.join(', ')}</td>

              <td>
                {hasPermission(me.permissions, 'grant:revoke') && (
                  <button
                    data-testid="revoke-grant"
                    data-permission="grant:revoke"
                    data-state="unlocked"
                  >
                    Revoke
                  </button>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function Sessions({ token, me }) {
  const [sessions, setSessions] = useState([]);

  useEffect(() => {
    request(`/orgs/${me.orgId}/sessions`, { token })
      .then((data) => setSessions(data.sessions));
  }, [token, me.orgId]);

  return (
    <div>
      <h2>Sessions</h2>

      {hasPermission(me.permissions, 'session:start') && (
        <button
          data-testid="new-session"
          data-permission="session:start"
          data-state="unlocked"
        >
          New session
        </button>
      )}

      {sessions.map((session) => (
        <div
          key={session.id}
          data-testid="session-row"
        >
          {session.mode} — {session.state}
        </div>
      ))}
    </div>
  );
}

function Audit({ token, me }) {
  const [events, setEvents] = useState([]);

  useEffect(() => {
    request(`/orgs/${me.orgId}/audit`, { token })
      .then((data) => setEvents(data.events));
  }, [token, me.orgId]);

  return (
    <div>
      <h2>Audit</h2>

      {events.map((event) => (
        <div key={event.id} data-testid="audit-row">
          {event.action} — {event.result}
        </div>
      ))}
    </div>
  );
}

function Admin({ me }) {
  return (
    <div>
      <h2>Admin</h2>

      {hasPermission(me.permissions, 'org:update') && (
        <button
          data-testid="rename-org"
          data-permission="org:update"
          data-state="unlocked"
        >
          Rename organization
        </button>
      )}

      {hasPermission(me.permissions, 'org:delete') && (
        <button
          data-testid="delete-org"
          data-permission="org:delete"
          data-state="unlocked"
        >
          Delete organization
        </button>
      )}
    </div>
  );
}

function Console({ token, me, onSwitchOrg, onCreateOrg, onSignOut }) {
  const [view, setView] = useState('devices');

  const p = me.permissions;

  const cards = [
    ['devices', 'Devices', 'device:list'],
    ['people', 'People', 'user:read'],
    ['grants', 'Grants', 'user:read'],
    ['sessions', 'Sessions', 'session:view'],
    ['audit', 'Audit', 'audit:read'],
  ];

  const background =
    THEMES[me.org.theme] ||
    `hsl(${me.org.id.length * 29 % 360} 65% 94%)`;

  function renderView() {
    if (view === 'devices') {
      return <Devices key={`${me.orgId}-${view}`} token={token} me={me} />;
    }

    if (view === 'people') {
      return <People token={token} me={me} />;
    }

    if (view === 'grants') {
      return <Grants token={token} me={me} />;
    }

    if (view === 'sessions') {
      return <Sessions token={token} me={me} />;
    }

    if (view === 'audit') {
      return <Audit token={token} me={me} />;
    }

    if (view === 'admin') {
      return <Admin me={me} />;
    }

    return null;
  }

  return (
    <div
      data-testid="app-shell"
      data-org-id={me.orgId}
      data-org-theme={me.org.theme}
      style={{
        ...styles.shell,
        backgroundColor: background,
      }}
    >
      <aside style={styles.sidebar}>
        <h1>RemoteOps</h1>

        <div>
          <strong>{me.org.name}</strong>
          <div>
            Role: <span data-testid="active-role">{me.role}</span>
          </div>
        </div>

        <hr />

        <div>
          {me.orgs.map((org) => (
            <button
              key={org.id}
              data-testid="org-option"
              data-org-id={org.id}
              onClick={() => onSwitchOrg(org.id)}
              style={styles.navButton}
            >
              {org.name}
            </button>
          ))}
        </div>

        <button
          data-testid="create-org"
          onClick={onCreateOrg}
          style={styles.navButton}
        >
          + Create organization
        </button>

        <hr />

        {cards.map(([key, label, permission]) =>
          hasPermission(p, permission) ? (
            <button
              key={key}
              data-testid={`nav-${key}`}
              data-permission={permission}
              data-state="unlocked"
              onClick={() => setView(key)}
              style={styles.navButton}
            >
              {label}
            </button>
          ) : null
        )}

        {(hasPermission(p, 'org:update') ||
          hasPermission(p, 'org:delete')) && (
          <button
            data-testid="nav-admin"
            data-permission={
              hasPermission(p, 'org:update')
                ? 'org:update'
                : 'org:delete'
            }
            data-state="unlocked"
            onClick={() => setView('admin')}
            style={styles.navButton}
          >
            Admin
          </button>
        )}

        <button onClick={onSignOut} style={styles.navButton}>
          Sign out
        </button>
      </aside>

      <main style={styles.content}>{renderView()}</main>
    </div>
  );
}

function App() {
  const inviteMatch = window.location.pathname.match(
    /^\/invite\/(.+)$/
  );

  const [inviteFinished, setInviteFinished] = useState(false);
  const [token, setToken] = useState(null);
  const [me, setMe] = useState(null);
  const [booting, setBooting] = useState(true);

  async function loadMe(accessToken) {
    const data = await request('/auth/me', {
      token: accessToken,
    });

    setToken(accessToken);
    setMe(data);
  }

  useEffect(() => {
    if (inviteMatch) {
      setBooting(false);
      return;
    }

    // Restore session after reload using HttpOnly refresh cookie.
    request('/auth/refresh', {
      method: 'POST',
    })
      .then((data) => loadMe(data.token))
      .catch(() => {
        setToken(null);
        setMe(null);
      })
      .finally(() => setBooting(false));
  }, []);

  async function switchOrg(orgId) {
    const switched = await request('/auth/token', {
      token,
      method: 'POST',
      body: { orgId },
    });

    const nextMe = await request('/auth/me', {
      token: switched.token,
    });

    setToken(switched.token);
    setMe(nextMe);
  }

  async function createOrg() {
    const name = window.prompt('Organization name');

    if (!name?.trim()) return;

    const created = await request('/orgs', {
      token,
      method: 'POST',
      body: { name: name.trim() },
    });

    await switchOrg(created.id);
  }

  if (inviteMatch && !inviteFinished) {
    return (
      <InvitePage
        inviteToken={decodeURIComponent(inviteMatch[1])}
        onFinished={() => {
          window.history.replaceState({}, '', '/');
          setInviteFinished(true);
        }}
      />
    );
  }

  if (booting) {
    return <main style={styles.loginPage}>Loading…</main>;
  }

  if (!token || !me) {
    return <Login onLogin={loadMe} />;
  }

  return (
    <Console
      token={token}
      me={me}
      onSwitchOrg={switchOrg}
      onCreateOrg={createOrg}
      onSignOut={() => {
        setToken(null);
        setMe(null);
      }}
    />
  );
}

const styles = {
  loginPage: {
    minHeight: '100vh',
    display: 'grid',
    placeItems: 'center',
    fontFamily: 'system-ui, sans-serif',
    background: '#f5f7fb',
  },

  loginCard: {
    display: 'grid',
    gap: 14,
    width: 360,
    padding: 28,
    background: 'white',
    borderRadius: 14,
    boxShadow: '0 8px 30px rgba(0,0,0,.08)',
  },

  input: {
    display: 'block',
    width: '100%',
    boxSizing: 'border-box',
    padding: 10,
    marginTop: 5,
  },

  primaryButton: {
    padding: 11,
    cursor: 'pointer',
  },

  error: {
    padding: 10,
    background: '#fee',
    border: '1px solid #d88',
  },

  shell: {
    minHeight: '100vh',
    display: 'grid',
    gridTemplateColumns: '250px 1fr',
    fontFamily: 'system-ui, sans-serif',
  },

  sidebar: {
    padding: 20,
    background: 'rgba(255,255,255,.82)',
  },

  content: {
    padding: 30,
  },

  navButton: {
    display: 'block',
    width: '100%',
    textAlign: 'left',
    margin: '6px 0',
    padding: 9,
    cursor: 'pointer',
  },
};

createRoot(document.getElementById('root')).render(<App />);