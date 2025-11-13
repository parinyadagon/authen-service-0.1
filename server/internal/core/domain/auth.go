package domain

import "time"

type AuthReq struct {
	UserName   string `json:"user_name"`
	Password   string `json:"password"`
	RememberMe bool   `json:"remember_me"`
	AuthType   string `json:"auth_type,omitempty"` // "cookie" or "jwt"
}

type AuthResp struct {
	AccessToken  string   `json:"access_token,omitempty"`  // For JWT auth
	RefreshToken string   `json:"refresh_token,omitempty"` // For JWT auth
	SessionToken string   `json:"session_token,omitempty"` // For cookie auth
	User         UserResp `json:"user"`
	AuthType     string   `json:"auth_type"` // Response type used
}

// UserSession represents a user session for cookie-based authentication with enhanced security
type UserSession struct {
	SessionToken string    `json:"session_token"`
	UserID       string    `json:"user_id"`
	ClientID     string    `json:"client_id"`
	ExpiresAt    time.Time `json:"expires_at"`
	IsActive     bool      `json:"is_active"`
	CreatedAt    time.Time `json:"created_at"`
	IPAddress    string    `json:"ip_address,omitempty"`    // Track IP for security
	UserAgent    string    `json:"user_agent,omitempty"`    // Track device info
	DeviceID     string    `json:"device_id,omitempty"`     // Device fingerprint
	LastAccessed time.Time `json:"last_accessed,omitempty"` // Track activity
}

type Authorize struct {
	UserID              string    `json:"user_id"`
	ClientID            string    `json:"client_id"`
	Scopes              string    `json:"scopes"`
	RedirectURI         string    `json:"redirect_uri"`
	CodeChallenge       string    `json:"code_challenge"`
	CodeChallengeMethod string    `json:"code_challenge_method"`
	ExpiresAt           time.Time `json:"expires_at"`
}

type UserConsent struct {
	UserID        string `json:"user_id"`
	ClientID      string `json:"client_id"`
	ScopesGranted string `json:"Scopes_granted"`
}

type RegisterReq struct {
	UserName  string `json:"user_name"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	Email     string `json:"email"`
	Password  string `json:"password"`
}

type RegisterResp struct {
	UserName  string `json:"user_name"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	Email     string `json:"email"`
}

type RefreshReq struct {
	RefreshToken string `json:"refresh_token"`
}

type RefreshResp struct {
	RefreshToken string `json:"refresh_token"`
	AccessToken  string `json:"access_token"`
}

// OAuth2 Authorization Code Flow types
type AuthorizeReq struct {
	ClientID            string `json:"client_id" form:"client_id"`
	RedirectURI         string `json:"redirect_uri" form:"redirect_uri"`
	Scope               string `json:"scope" form:"scope"`
	State               string `json:"state" form:"state"`
	ResponseType        string `json:"response_type" form:"response_type"`
	CodeChallenge       string `json:"code_challenge" form:"code_challenge"`
	CodeChallengeMethod string `json:"code_challenge_method" form:"code_challenge_method"`
}

type AuthorizeResp struct {
	Code        string `json:"code"`
	State       string `json:"state"`
	RedirectURI string `json:"redirect_uri"`
}

type TokenReq struct {
	GrantType    string `json:"grant_type" form:"grant_type"`
	Code         string `json:"code" form:"code"`
	ClientID     string `json:"client_id" form:"client_id"`
	ClientSecret string `json:"client_secret" form:"client_secret"`
	RedirectURI  string `json:"redirect_uri" form:"redirect_uri"`
	CodeVerifier string `json:"code_verifier" form:"code_verifier"`
}

type TokenResp struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// Session response types for frontend
type SessionInfo struct {
	SessionID    string    `json:"session_id"`
	DeviceID     string    `json:"device_id"`
	IPAddress    string    `json:"ip_address"`
	UserAgent    string    `json:"user_agent"`
	LastAccessed time.Time `json:"last_accessed"`
	CreatedAt    time.Time `json:"created_at"`
	IsCurrent    bool      `json:"is_current"`
	ExpiresAt    time.Time `json:"expires_at"`
}

type GetSessionsResp struct {
	Sessions     []SessionInfo `json:"sessions"`
	TotalCount   int           `json:"total_count"`
	MaxSessions  int           `json:"max_sessions"`
	CurrentToken string        `json:"current_token,omitempty"` // For identifying current session
}

// Authorization Code entity
type AuthorizationCode struct {
	Code                string    `json:"code"`
	UserID              string    `json:"user_id"`
	ClientID            string    `json:"client_id"`
	Scopes              string    `json:"scopes"`
	RedirectURI         string    `json:"redirect_uri"`
	CodeChallenge       string    `json:"code_challenge"`
	CodeChallengeMethod string    `json:"code_challenge_method"`
	ExpiresAt           time.Time `json:"expires_at"`
	Used                bool      `json:"used"`
}
