package ports

import (
	"context"
	"server/internal/core/domain"
	"time"
)

type AuthServicePort interface {
	// User authentication
	Login(ctx context.Context, authReq *domain.AuthReq) (*domain.AuthResp, error)
	Refresh(ctx context.Context, refreshToken string) (*domain.RefreshResp, error)
	Register(ctx context.Context, registerReq *domain.RegisterReq) (*domain.RegisterResp, error)

	// OAuth2 Authorization Code Flow
	Authorize(ctx context.Context, req *domain.AuthorizeReq, userID string) (*domain.AuthorizeResp, error)
	Token(ctx context.Context, req *domain.TokenReq) (*domain.TokenResp, error)

	// Session management (for cookie-based auth)
	InvalidateSession(ctx context.Context, sessionToken string) error
	RefreshSession(ctx context.Context, refreshToken string) (*domain.AuthResp, error)
	InvalidateAllUserSessions(ctx context.Context, userID string) error
	DetectSessionCompromise(ctx context.Context, sessionToken, currentIP, currentUserAgent string) (bool, error)
}

type AuthRepositoryPort interface {
	// User operations
	FindUserByID(ctx context.Context, userID string) (*domain.User, error)
	FindUserByUserName(ctx context.Context, username string) (*domain.User, error)
	FindUserByEmail(ctx context.Context, email string) (*domain.User, error)
	CreateUser(ctx context.Context, user *domain.UserWithRole) error
	IsEmailExists(ctx context.Context, email string) (int, error)
	IsUsernameExists(ctx context.Context, username string) (int, error)

	// Role operations
	FindRoleByName(ctx context.Context, roleName string) (*domain.Role, error)
	GetDefaultRole(ctx context.Context) (*domain.Role, error)

	// OAuth2 Client operations
	FindClientByID(ctx context.Context, clientID string) (*domain.Client, error)
	ValidateClientCredentials(ctx context.Context, clientID, clientSecret string) (*domain.Client, error)

	// Authorization Code operations
	CreateAuthorizationCode(ctx context.Context, code *domain.AuthorizationCode) error
	FindAuthorizationCode(ctx context.Context, code string) (*domain.AuthorizationCode, error)
	DeleteAuthorizationCode(ctx context.Context, code string) error

	// Access Token operations (for opaque tokens)
	StoreAccessToken(ctx context.Context, token *domain.AccessToken) error
	FindAccessToken(ctx context.Context, tokenID string) (*domain.AccessToken, error)
	RevokeAccessToken(ctx context.Context, tokenID string) error

	// Refresh Token operations
	StoreRefreshToken(ctx context.Context, token *domain.RefreshToken) error
	FindRefreshToken(ctx context.Context, tokenID string) (*domain.RefreshToken, error)
	RevokeRefreshToken(ctx context.Context, tokenID string) error
	RevokeAllUserTokens(ctx context.Context, userID string) error

	// User Consent operations
	CreateUserConsent(ctx context.Context, consent *domain.UserConsent) error
	FindUserConsent(ctx context.Context, userID, clientID string) (*domain.UserConsent, error)

	// User Session operations (for cookie-based auth)
	StoreUserSession(ctx context.Context, session *domain.UserSession) error
	FindUserSession(ctx context.Context, sessionToken string) (*domain.UserSession, error)
	InvalidateUserSession(ctx context.Context, sessionToken string) error
	RevokeAllUserSessions(ctx context.Context, userID string) error
	FindActiveUserSessions(ctx context.Context, userID string) ([]*domain.UserSession, error)
	CleanupExpiredSessions(ctx context.Context, userID string) error
	UpdateSessionAccess(ctx context.Context, sessionToken string, lastAccessed time.Time) error
	ExtendSession(ctx context.Context, sessionToken string, newExpiry time.Time) error
}
