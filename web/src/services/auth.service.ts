import type { LoginRequest, LoginResponse, UserProfile, SessionInfo } from "../types/auth.types";

// API Base URL - adjust based on your backend
const API_BASE_URL = "http://localhost:8080";

// Debug mode - set to false in production
const DEBUG_AUTH = true;

// Simple cache to prevent duplicate auth checks
let authCache: { result: { isAuthenticated: boolean; user?: UserProfile }; timestamp: number } | null = null;
const CACHE_DURATION = 5000; // 5 seconds

// Helper to clear auth cache
const clearAuthCache = () => {
  authCache = null;
  debugLog("🗑️ Auth cache cleared");
};

// Debug helper
const debugLog = (message: string, ...args: unknown[]) => {
  if (DEBUG_AUTH) {
    console.log(`🔐 AuthService: ${message}`, ...args);
  }
};

/**
 * Authentication Service
 * Handles all authentication-related API calls
 */
export class AuthService {
  /**
   * Hybrid Login - supports both Cookie and JWT authentication
   */
  static async login(credentials: LoginRequest): Promise<LoginResponse> {
    try {
      const response = await fetch(`${API_BASE_URL}/api/auth/login`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        credentials: "include", // Important for cookie authentication
        body: JSON.stringify({
          user_name: credentials.username,
          password: credentials.password,
        }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || data.message || "Login failed");
      }

      // Store JWT token if provided
      if (data.access_token) {
        if (credentials.remember) {
          localStorage.setItem("access_token", data.access_token);
          localStorage.setItem("token_type", data.token_type || "Bearer");
        } else {
          sessionStorage.setItem("access_token", data.access_token);
          sessionStorage.setItem("token_type", data.token_type || "Bearer");
        }
      }

      // Store user data from login response
      if (data.user) {
        const userData = {
          ...data.user,
          auth_type: data.auth_type,
          login_time: new Date().toISOString(),
        };
        const storage = credentials.remember ? localStorage : sessionStorage;
        storage.setItem("user_data", JSON.stringify(userData));
        debugLog("User data stored:", userData);
      }

      // Clear auth cache after successful login
      clearAuthCache();

      return data;
    } catch (error) {
      if (error instanceof Error) {
        throw error;
      }
      throw new Error("Network error occurred");
    }
  }

  /**
   * Register new user
   */
  static async register(userData: { username: string; email: string; password: string; firstName: string; lastName: string }): Promise<void> {
    const response = await fetch(`${API_BASE_URL}/api/auth/register`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        user_name: userData.username,
        email: userData.email,
        password: userData.password,
        first_name: userData.firstName,
        last_name: userData.lastName,
      }),
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.message || "Registration failed");
    }
  }

  /**
   * Logout from the system
   */
  static async logout(): Promise<void> {
    try {
      await fetch(`${API_BASE_URL}/api/auth/logout`, {
        method: "POST",
        credentials: "include",
        headers: {
          ...this.getAuthHeaders(),
        },
      });
    } catch (error) {
      console.error("Logout error:", error);
    } finally {
      // Clear stored tokens and auth cache
      this.clearTokens();
      clearAuthCache();
    }
  }

  /**
   * Get current user profile
   */
  static async getProfile(): Promise<UserProfile> {
    // First try to get stored user data from login
    const storedUser = localStorage.getItem("user_data") || sessionStorage.getItem("user_data");

    if (storedUser) {
      try {
        const userData = JSON.parse(storedUser);
        debugLog("Using cached user data:", userData);
        return userData;
      } catch (parseError) {
        debugLog("Failed to parse stored user data:", parseError);
      }
    }

    // Fallback to API call
    debugLog("Fetching profile from API...");
    const response = await ApiClient.get("/api/profile");

    if (!response.ok) {
      throw new Error("Failed to fetch profile");
    }

    const profileData = await response.json();
    debugLog("Profile from API:", profileData);
    return profileData;
  }

  /**
   * Check session status (lightweight endpoint for auth verification)
   */
  static async checkSession(): Promise<{ valid: boolean; user_id?: string; auth_type?: string }> {
    try {
      const response = await fetch(`${API_BASE_URL}/api/auth/session-status`, {
        method: "GET",
        credentials: "include",
        headers: {
          ...this.getAuthHeaders(),
        },
      });

      if (response.ok) {
        return await response.json();
      } else {
        return { valid: false };
      }
    } catch {
      return { valid: false };
    }
  }

  /**
   * Get active user sessions
   */
  static async getSessions(): Promise<SessionInfo[]> {
    const response = await ApiClient.get("/api/auth/sessions");

    if (!response.ok) {
      throw new Error("Failed to fetch sessions");
    }

    const data = await response.json();
    debugLog("Sessions API response:", data);

    // Extract sessions from the response data structure
    if (data.data && data.data.sessions) {
      return data.data.sessions;
    }

    // Fallback if response structure is different
    return data.sessions || [];
  }

  /**
   * Revoke a specific session
   */
  static async revokeSession(sessionId: string): Promise<void> {
    const response = await ApiClient.delete(`/api/auth/sessions/${sessionId}`);

    if (!response.ok) {
      throw new Error("Failed to revoke session");
    }
  }

  /**
   * Revoke all sessions
   */
  static async revokeAllSessions(): Promise<void> {
    const response = await fetch(`${API_BASE_URL}/api/auth/revoke-all`, {
      method: "POST",
      credentials: "include",
      headers: {
        ...this.getAuthHeaders(),
      },
    });

    if (!response.ok) {
      throw new Error("Failed to revoke sessions");
    }

    // Clear local tokens and auth cache after successful revoke
    this.clearTokens();
    clearAuthCache();
  }

  /**
   * Check if user is authenticated (async version)
   * This method verifies authentication with the backend server
   */
  static async isAuthenticated(): Promise<boolean> {
    const token = this.getToken();

    debugLog("JWT token present:", !!token);

    // Always verify with backend regardless of local tokens
    // This ensures we catch expired sessions and HttpOnly cookies
    const result = await this.verifyAuthStatus();
    return result.isAuthenticated;
  }

  /**
   * Check authentication and get user data in one call
   * More efficient than separate isAuthenticated() + getProfile() calls
   */
  static async checkAuthWithUser(): Promise<{ isAuthenticated: boolean; user?: UserProfile }> {
    return await this.verifyAuthStatus();
  }

  /**
   * Quick synchronous check for JWT token only
   * Use this when you need immediate response without server verification
   */
  static hasLocalToken(): boolean {
    const token = this.getToken();
    debugLog("Local token check:", !!token);
    return !!token;
  }

  /**
   * Get stored JWT token
   */
  static getToken(): string | null {
    return localStorage.getItem("access_token") || sessionStorage.getItem("access_token");
  }

  /**
   * Get token type
   */
  static getTokenType(): string {
    return localStorage.getItem("token_type") || sessionStorage.getItem("token_type") || "Bearer";
  }

  /**
   * Get authorization headers
   */
  static getAuthHeaders(): Record<string, string> {
    const token = this.getToken();
    const tokenType = this.getTokenType();

    if (token) {
      return {
        Authorization: `${tokenType} ${token}`,
      };
    }

    return {};
  }

  /**
   * Clear all stored tokens and user data
   */
  static clearTokens(): void {
    localStorage.removeItem("access_token");
    localStorage.removeItem("token_type");
    localStorage.removeItem("user_data");
    sessionStorage.removeItem("access_token");
    sessionStorage.removeItem("token_type");
    sessionStorage.removeItem("user_data");
    debugLog("All stored data cleared");
  }

  /**
   * Verify authentication status by calling a protected endpoint
   * This checks both JWT tokens and HttpOnly session cookies with the backend
   * Returns both auth status and user data if available
   */
  static async verifyAuthStatus(): Promise<{ isAuthenticated: boolean; user?: UserProfile }> {
    try {
      // Check cache first to prevent duplicate calls
      const now = Date.now();
      if (authCache && now - authCache.timestamp < CACHE_DURATION) {
        console.log("📦 Using cached auth result");
        return authCache.result;
      }

      console.log("🔍 Verifying authentication with lightweight endpoint...");

      const response = await fetch(`${API_BASE_URL}/api/auth/check`, {
        method: "GET",
        credentials: "include", // Critical: includes HttpOnly cookies
        headers: {
          ...this.getAuthHeaders(),
        },
      });

      const isAuthenticated = response.ok;
      console.log(`🔐 Auth verification result: ${isAuthenticated ? "✅ Authenticated" : "❌ Not authenticated"} (${response.status})`);

      let result: { isAuthenticated: boolean; user?: UserProfile };

      if (isAuthenticated) {
        try {
          const data = await response.json();
          console.log("👤 User info from auth check:", data.user_id || "Unknown user");

          // If the response includes user data, return it to avoid another API call
          if (data.user || (data.user_id && data.username)) {
            const userData = data.user || {
              id: data.user_id,
              username: data.username,
              first_name: data.first_name,
              last_name: data.last_name,
              email: data.email,
            };
            result = { isAuthenticated: true, user: userData };
          } else {
            result = { isAuthenticated: true };
          }
        } catch (parseError) {
          console.log("📄 Got response but couldn't parse JSON:", parseError);
          result = { isAuthenticated: true };
        }
      } else {
        console.log("❗ Authentication failed - may need to login");
        result = { isAuthenticated: false };
      }

      // Cache the result
      authCache = { result, timestamp: now };
      return result;
    } catch (error) {
      console.error("🚨 Auth verification network error:", error);
      const result = { isAuthenticated: false };
      authCache = { result, timestamp: Date.now() };
      return result;
    }
  }

  /**
   * Refresh JWT token using the refresh token endpoint
   */
  static async refreshToken(): Promise<void> {
    try {
      const response = await fetch(`${API_BASE_URL}/api/auth/refresh`, {
        method: "POST",
        credentials: "include",
        headers: {
          ...this.getAuthHeaders(),
        },
      });

      if (!response.ok) {
        throw new Error("Token refresh failed");
      }

      const data = await response.json();

      if (data.access_token) {
        // Update stored token
        const isRemembered = localStorage.getItem("access_token");
        if (isRemembered) {
          localStorage.setItem("access_token", data.access_token);
        } else {
          sessionStorage.setItem("access_token", data.access_token);
        }
      }
    } catch (error) {
      // If refresh fails, logout user
      await this.logout();
      throw error;
    }
  }
}

/**
 * HTTP Client with automatic token refresh
 */
export class ApiClient {
  static async request(url: string, options: RequestInit = {}) {
    const fullUrl = url.startsWith("http") ? url : `${API_BASE_URL}${url}`;

    const requestOptions: RequestInit = {
      ...options,
      credentials: "include",
      headers: {
        "Content-Type": "application/json",
        ...AuthService.getAuthHeaders(),
        ...options.headers,
      },
    };

    let response = await fetch(fullUrl, requestOptions);

    // If token expired, try to refresh
    if (response.status === 401 && AuthService.getToken()) {
      try {
        await AuthService.refreshToken();

        // Retry the request with new token
        requestOptions.headers = {
          ...requestOptions.headers,
          ...AuthService.getAuthHeaders(),
        };

        response = await fetch(fullUrl, requestOptions);
      } catch {
        // Refresh failed, user needs to login again
        throw new Error("Session expired. Please login again.");
      }
    }

    return response;
  }

  static async get(url: string) {
    return this.request(url, { method: "GET" });
  }

  static async post(url: string, data?: unknown) {
    return this.request(url, {
      method: "POST",
      body: data ? JSON.stringify(data) : undefined,
    });
  }

  static async put(url: string, data?: unknown) {
    return this.request(url, {
      method: "PUT",
      body: data ? JSON.stringify(data) : undefined,
    });
  }

  static async delete(url: string) {
    return this.request(url, { method: "DELETE" });
  }
}
