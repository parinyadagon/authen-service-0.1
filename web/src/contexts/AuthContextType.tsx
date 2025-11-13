import { createContext } from "react";
import type { AuthState, LoginRequest } from "../types/auth.types";

export interface AuthContextType extends AuthState {
  login: (credentials: LoginRequest) => Promise<void>;
  logout: () => Promise<void>;
  refreshAuth: () => Promise<void>;
  revokeAllSessions: () => Promise<void>;
}

export const AuthContext = createContext<AuthContextType | null>(null);
