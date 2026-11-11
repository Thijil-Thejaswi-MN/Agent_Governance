import React, { createContext, useContext, useEffect, useState } from 'react';
import { getOperatorToken, setOperatorToken, clearOperatorToken, api, UNAUTHORIZED_EVENT } from '../api/client';
import { Role, UserSession } from '../types';

interface AuthContextType {
  token: string | null;
  hasToken: boolean;
  user: UserSession | null;
  role: Role;
  team: string | null;
  landingRoute: string;
  isDemoDataActive: boolean;
  isConfigured: boolean | null;
  isModalOpen: boolean;
  needsSignIn: boolean;
  authEpoch: number;
  /** The first auth-status request has answered (or failed). */
  authChecked: boolean;
  saveToken: (token: string) => Promise<{ user?: UserSession; landing_route?: string }>;
  removeToken: () => void;
  openAuthModal: () => void;
  closeAuthModal: () => void;
}

const AuthContext = createContext<AuthContextType>({
  token: null,
  hasToken: false,
  user: null,
  role: 'admin',
  team: null,
  landingRoute: '/',
  isDemoDataActive: false,
  isConfigured: null,
  isModalOpen: false,
  needsSignIn: false,
  authEpoch: 0,
  authChecked: false,
  saveToken: async () => ({}),
  removeToken: () => {},
  openAuthModal: () => {},
  closeAuthModal: () => {},
});

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [token, setTokenState] = useState<string | null>(() => getOperatorToken());
  const [user, setUser] = useState<UserSession | null>(null);
  const [role, setRole] = useState<Role>('admin');
  const [team, setTeam] = useState<string | null>(null);
  const [landingRoute, setLandingRoute] = useState<string>('/');
  const [isDemoDataActive, setIsDemoDataActive] = useState<boolean>(false);
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [isConfigured, setIsConfigured] = useState<boolean | null>(null);
  const [needsSignIn, setNeedsSignIn] = useState(false);
  const [authEpoch, setAuthEpoch] = useState(0);
  const [authChecked, setAuthChecked] = useState(false);

  useEffect(() => {
    const onUnauthorized = () => setNeedsSignIn(true);
    window.addEventListener(UNAUTHORIZED_EVENT, onUnauthorized);
    return () => window.removeEventListener(UNAUTHORIZED_EVENT, onUnauthorized);
  }, []);

  useEffect(() => {
    api.getAuthStatus()
      .then(res => {
        setIsConfigured(res.operator_token_configured);
        setIsDemoDataActive(!!(res as any).demo_data_active);
        if ((res as any).user) {
          setUser((res as any).user);
          setRole((res as any).user.role || 'admin');
          setTeam((res as any).user.team || null);
          setLandingRoute((res as any).landing_route || '/');
        }
        const stored = getOperatorToken();
        if (stored && !res.session_active) {
          api.createSession(stored)
            .then(sessRes => {
              if ((sessRes as any).user) {
                setUser((sessRes as any).user);
                setRole((sessRes as any).user.role || 'admin');
                setTeam((sessRes as any).user.team || null);
                setLandingRoute((sessRes as any).landing_route || '/');
              }
            })
            .catch(() => {
              clearOperatorToken();
              setTokenState(null);
              setUser(null);
              setNeedsSignIn(true);
            });
        }
      })
      .catch(() => setIsConfigured(null))
      .finally(() => setAuthChecked(true));
  }, [authEpoch]);

  const saveToken = async (newToken: string) => {
    const trimmed = newToken.trim();
    const sessRes = await api.createSession(trimmed);
    setOperatorToken(trimmed);
    setTokenState(trimmed);
    if ((sessRes as any).user) {
      setUser((sessRes as any).user);
      setRole((sessRes as any).user.role || 'admin');
      setTeam((sessRes as any).user.team || null);
      setLandingRoute((sessRes as any).landing_route || '/');
    }
    setIsModalOpen(false);
    setNeedsSignIn(false);
    setAuthEpoch(e => e + 1);
    return sessRes as any;
  };

  const removeToken = () => {
    api.deleteSession().catch(() => {});
    clearOperatorToken();
    setTokenState(null);
    setUser(null);
    setRole('admin');
    setTeam(null);
    setNeedsSignIn(true);
  };

  const openAuthModal = () => setIsModalOpen(true);
  const closeAuthModal = () => setIsModalOpen(false);

  return (
    <AuthContext.Provider
      value={{
        token,
        hasToken: !!token,
        user,
        role,
        team,
        landingRoute,
        isDemoDataActive,
        isConfigured,
        isModalOpen,
        needsSignIn,
        authEpoch,
        authChecked,
        saveToken,
        removeToken,
        openAuthModal,
        closeAuthModal,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => useContext(AuthContext);
