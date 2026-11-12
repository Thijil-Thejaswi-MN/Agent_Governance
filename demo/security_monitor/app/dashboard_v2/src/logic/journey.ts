// Where /dashboard sends people: the sign-in page without a session, otherwise the role's home.
// Developer and admin both start on Run.
import { Role } from '../types';

export const ROLE_HOME: Record<Role, string> = {
  developer: '/run',
  admin: '/run',
  team_lead: '/team',
  security_reviewer: '/inbox',
  auditor: '/records',
};

export function roleHome(role?: Role | null): string {
  return (role && ROLE_HOME[role]) || '/run';
}

export interface RootRedirectInput {
  /** The first auth-status request has answered (or failed). */
  authChecked: boolean;
  /** An operator token is stored in this tab. */
  hasToken: boolean;
  /** The server reported a signed-in user (a session). */
  role: Role | null;
}

/**
 * The route for /dashboard, or null while it cannot be known yet (auth status still loading,
 * or a stored token whose session is still being created).
 */
export function rootRedirect({ authChecked, hasToken, role }: RootRedirectInput): string | null {
  if (!authChecked) return null;
  if (role) return roleHome(role);
  return hasToken ? null : '/signin';
}
