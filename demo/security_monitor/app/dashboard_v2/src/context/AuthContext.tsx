import React, { createContext, useContext, useEffect, useState } from 'react';
import { getOperatorToken, setOperatorToken, clearOperatorToken, api } from '../api/client';

interface AuthContextType {
  token: string | null;
  hasToken: boolean;
  isConfigured: boolean | null;
  isModalOpen: boolean;
  saveToken: (token: string) => void;
  removeToken: () => void;
  openAuthModal: () => void;
  closeAuthModal: () => void;
}

const AuthContext = createContext<AuthContextType>({
  token: null,
  hasToken: false,
  isConfigured: null,
  isModalOpen: false,
  saveToken: () => {},
  removeToken: () => {},
  openAuthModal: () => {},
  closeAuthModal: () => {},
});

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [token, setTokenState] = useState<string | null>(() => getOperatorToken());
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [isConfigured, setIsConfigured] = useState<boolean | null>(null);

  useEffect(() => {
    api.getAuthStatus()
      .then(res => setIsConfigured(res.operator_token_configured))
      .catch(() => setIsConfigured(null));
  }, []);

  const saveToken = (newToken: string) => {
    setOperatorToken(newToken);
    setTokenState(newToken.trim());
    setIsModalOpen(false);
  };

  const removeToken = () => {
    clearOperatorToken();
    setTokenState(null);
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
