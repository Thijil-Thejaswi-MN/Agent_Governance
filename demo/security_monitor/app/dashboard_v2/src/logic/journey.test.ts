import { describe, expect, it } from 'vitest';
import { Role } from '../types';
import { roleHome, rootRedirect } from './journey';

describe('rootRedirect (/dashboard)', () => {
  it('waits until the auth status has answered', () => {
    expect(rootRedirect({ authChecked: false, hasToken: false, role: null })).toBeNull();
    expect(rootRedirect({ authChecked: false, hasToken: true, role: 'admin' })).toBeNull();
  });

  it('sends a visitor without a session to sign-in', () => {
    expect(rootRedirect({ authChecked: true, hasToken: false, role: null })).toBe('/signin');
  });

  it('waits while a stored token is still turning into a session', () => {
    expect(rootRedirect({ authChecked: true, hasToken: true, role: null })).toBeNull();
  });

  it("sends a signed-in user to their role's home; developer and admin go to Run", () => {
    const at = (role: Role) => rootRedirect({ authChecked: true, hasToken: true, role });
    expect(at('developer')).toBe('/run');
    expect(at('admin')).toBe('/run');
    expect(at('team_lead')).toBe('/team');
    expect(at('security_reviewer')).toBe('/inbox');
    expect(at('auditor')).toBe('/records');
  });

  it('a session cookie without a token in this tab still counts as signed in', () => {
    expect(rootRedirect({ authChecked: true, hasToken: false, role: 'auditor' })).toBe('/records');
  });

  it('never sends anyone to the old Home page', () => {
    for (const role of ['developer', 'admin', 'team_lead', 'security_reviewer', 'auditor'] as const) {
      expect(roleHome(role)).not.toBe('/');
    }
    expect(roleHome(null)).toBe('/run');
  });
});
