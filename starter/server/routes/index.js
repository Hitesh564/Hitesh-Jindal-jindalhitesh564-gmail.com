import { registerAuthRoutes } from './auth.js';
import { registerOrgRoutes } from './orgs.js';
import { registerDeviceRoutes } from './devices.js';
import { registerSessionRoutes } from './sessions.js';
import { registerAuditRoutes } from './audit.js';
import { registerGrantRoutes } from './grants.js';
import { registerInviteRoutes } from './invites.js';

export function registerRoutes(router, deps) {
  registerAuthRoutes(router, deps);
  registerOrgRoutes(router, deps);
  registerDeviceRoutes(router, deps);
  registerGrantRoutes(router, deps);
  registerSessionRoutes(router, deps);
  registerAuditRoutes(router, deps);
  registerInviteRoutes(router, deps);
}