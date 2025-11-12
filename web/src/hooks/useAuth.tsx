import { useState, useEffect, useCallback } from "react";
import { AuthService } from "../services/auth.service";
import type { LoginRequest, AuthState } from "../types/auth.types";

export function useAuth() {
  const [authState, setAuthState] = useState<AuthState>({
    isAuthenticated: false,
    user: null,
    loading: true,
    error: null,
  });

  const checkAuthStatus = useCallback(async () => {
    try {
      setAuthState((prev) => ({ ...prev, loading: true, error: null }));
      console.log("🔄 Starting authentication check...");

      // Check authentication status with backend (includes both JWT and cookies)
      const isAuthenticated = await AuthService.isAuthenticated();

      if (isAuthenticated) {
        console.log("✅ User is authenticated, fetching profile...");
        try {
          const user = await AuthService.getProfile();
          setAuthState({
            isAuthenticated: true,
            user,
            loading: false,
            error: null,
          });
          console.log("👤 Profile loaded successfully:", user.username);
        } catch (profileErr) {
          console.log("⚠️ Authentication valid but profile fetch failed:", profileErr);
          // User is authenticated but we can't get their profile
          setAuthState({
            isAuthenticated: true,
            user: null,
            loading: false,
            error: "Could not load user profile",
          });
        }
      } else {
        console.log("❌ User is not authenticated");
        // Clear any stale local tokens
        AuthService.clearTokens();
        setAuthState({
          isAuthenticated: false,
          user: null,
          loading: false,
          error: null,
        });
      }
    } catch (error) {
      console.error("🚨 Authentication check failed:", error);
      setAuthState({
        isAuthenticated: false,
        user: null,
        loading: false,
        error: error instanceof Error ? error.message : "Authentication check failed",
      });
    }
  }, []);

  // Check initial authentication status
  useEffect(() => {
    checkAuthStatus();
  }, [checkAuthStatus]);

  const login = useCallback(async (credentials: LoginRequest): Promise<void> => {
    try {
      setAuthState((prev) => ({ ...prev, loading: true, error: null }));

      const response = await AuthService.login(credentials);

      setAuthState({
        isAuthenticated: true,
        user: response.user || null,
        loading: false,
        error: null,
      });
    } catch (error) {
      setAuthState((prev) => ({
        ...prev,
        loading: false,
        error: error instanceof Error ? error.message : "Login failed",
      }));
      throw error; // Re-throw so component can handle it
    }
  }, []);

  const logout = useCallback(async (): Promise<void> => {
    try {
      setAuthState((prev) => ({ ...prev, loading: true }));

      await AuthService.logout();

      setAuthState({
        isAuthenticated: false,
        user: null,
        loading: false,
        error: null,
      });
    } catch (error) {
      setAuthState((prev) => ({
        ...prev,
        loading: false,
        error: error instanceof Error ? error.message : "Logout failed",
      }));
    }
  }, []);

  const refreshAuth = useCallback(async (): Promise<void> => {
    await checkAuthStatus();
  }, [checkAuthStatus]);

  const revokeAllSessions = useCallback(async (): Promise<void> => {
    try {
      setAuthState((prev) => ({ ...prev, loading: true }));

      await AuthService.revokeAllSessions();

      setAuthState({
        isAuthenticated: false,
        user: null,
        loading: false,
        error: null,
      });
    } catch (error) {
      setAuthState((prev) => ({
        ...prev,
        loading: false,
        error: error instanceof Error ? error.message : "Failed to revoke sessions",
      }));
      throw error;
    }
  }, []);

  return {
    ...authState,
    login,
    logout,
    refreshAuth,
    revokeAllSessions,
  };
}
