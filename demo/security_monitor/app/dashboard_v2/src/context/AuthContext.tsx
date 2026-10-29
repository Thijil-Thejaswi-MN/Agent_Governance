import React, { createContext, useContext, useEffect, useState } from 'react';
import { getOperatorToken, setOperatorToken, clearOperatorToken, api, UNAUTHORIZED_EVENT } from '../api/client';

interface AuthContextType {
  token: string | null;
  hasToken: boolean;
  isConfigured: boolean | null;
  isModalOpen: boolean;
  // True after any API call returned 401: pages show the "sign in" state.
  needsSignIn: boolean;
  // Bumped on every successful sign-in so pages remount and refetch.
  authEpoch: number;
  saveToken: (token: string) => Promise<void>;
  removeToken: () => void;
  openAuthModal: () => void;
  closeAuthModal: () => void;
}

const AuthContext = createContext<AuthContextType>({
  token: null,
  hasToken: false,
  isConfigured: null,
  isModalOpen: false,
  needsSignIn: false,
  authEpoch: 0,
  saveToken: async () => {},
  removeToken: () => {},
  openAuthModal: () => {},
  closeAuthModal: () => {},
});

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [token, setTokenState] = useState<string | null>(() => getOperatorToken());
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [isConfigured, setIsConfigured] = useState<boolean | null>(null);
  const [needsSignIn, setNeedsSignIn] = useState(false);
  const [authEpoch, setAuthEpoch] = useState(0);

  useEffect(() => {
    const onUnauthorized = () => setNeedsSignIn(true);
    window.addEventListener(UNAUTHORIZED_EVENT, onUnauthorized);
    return () => window.removeEventListener(UNAUTHORIZED_EVENT, onUnauthorized);
  }, []);

  useEffect(() => {
    api.getAuthStatus()
      .then(res => {
        setIsConfigured(res.operator_token_configured);
        // A token kept from earlier in this tab: renew the read-session cookie (SSE needs it).
        const stored = getOperatorToken();
        if (stored && !res.session_active) {
          api.createSession(stored).catch(() => {
            clearOperatorToken();
            setTokenState(null);
            setNeedsSignIn(true);
          });
        }
      })
      .catch(() => setIsConfigured(null));
  }, []);

  // Throws if the server rejects the token, so the modal can show the error.
  const saveToken = async (newToken: string) => {
    const trimmed = newToken.trim();
    await api.createSession(trimmed);
    setOperatorToken(trimmed);
    setTokenState(trimmed);
    setIsModalOpen(false);
    setNeedsSignIn(false);
    setAuthEpoch(e => e + 1);
  };

  const removeToken = () => {
    api.deleteSession().catch(() => {});
    clearOperatorToken();
    setTokenState(null);
    setNeedsSignIn(true);
  };

  const openAuthModal = () => setIsModalOpen(true);
  const closeAuthModal = () => setIsModalOpen(false);

  return (
    <AuthContext.Provider
      value={{
        token,
        hasToken: !!token,
        isConfigured,
        isModalOpen,
        needsSignIn,
        authEpoch,
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
