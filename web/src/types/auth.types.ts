// Profile Types
export interface UserProfile {
  // Data from /api/profile endpoint (actual API response)
  user_id?: string;
  username?: string;
  auth_type?: string;
  message?: string;

  // Extended user data (if available from other endpoints)
  id?: string;
  email?: string;
  first_name?: string;
  last_name?: string;
  is_active?: boolean;
  is_verified?: boolean;
  roles?: string[];
  created_at?: string;
  last_login?: string;
}

// Authentication Types
export interface LoginRequest {
  username: string;
  password: string;
  remember?: boolean;
}

export interface LoginResponse {
  message: string;
  user?: UserProfile;
  access_token?: string;
  token_type?: string;
  expires_in?: number;
}

export interface ApiError {
  error: string;
  message?: string;
}

// Session Types
export interface SessionInfo {
  session_id: string;
  device_id: string;
  ip_address: string;
  user_agent: string;
  last_accessed: string;
  created_at: string;
  is_current: boolean;
  expires_at: string;
}

export interface GetSessionsResponse {
  sessions: SessionInfo[];
  total_count: number;
  max_sessions: number;
  current_token?: string;
}

// Auth State Types
export interface AuthState {
  isAuthenticated: boolean;
  user: UserProfile | null;
  loading: boolean;
  error: string | null;
}
