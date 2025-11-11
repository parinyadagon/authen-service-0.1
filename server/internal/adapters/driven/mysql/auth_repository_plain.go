package mysql

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"server/internal/core/domain"
	"server/internal/core/ports"

	_ "github.com/go-sql-driver/mysql"
)

type authRepository struct {
	db *sql.DB
}

func NewAuthRepository(db *sql.DB) ports.AuthRepositoryPort {
	return &authRepository{db: db}
}

// User operations
func (r *authRepository) FindUserByID(ctx context.Context, userID string) (*domain.User, error) {
	query := `
		SELECT id, username, password_hash, email, first_name, last_name, 
		       is_active, is_verified, created_at
		FROM users 
		WHERE id = ?`

	var user domain.User
	var firstName, lastName sql.NullString

	err := r.db.QueryRowContext(ctx, query, userID).Scan(
		&user.ID,
		&user.UserName,
		&user.Password,
		&user.Email,
		&firstName,
		&lastName,
		&user.IsActive,
		&user.IsVerified,
		&user.CreatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("user not found")
		}
		return nil, fmt.Errorf("failed to find user by ID: %w", err)
	}

	user.FirstName = firstName.String
	user.LastName = lastName.String
	user.UpdatedAt = user.CreatedAt

	return &user, nil
}

func (r *authRepository) FindUserByUserName(ctx context.Context, username string) (*domain.User, error) {
	query := `
		SELECT id, username, password_hash, email, first_name, last_name, 
		       is_active, is_verified, created_at
		FROM users 
		WHERE username = ?`

	var user domain.User
	var firstName, lastName sql.NullString

	err := r.db.QueryRowContext(ctx, query, username).Scan(
		&user.ID,
		&user.UserName,
		&user.Password,
		&user.Email,
		&firstName,
		&lastName,
		&user.IsActive,
		&user.IsVerified,
		&user.CreatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("user not found")
		}
		return nil, fmt.Errorf("failed to find user by username: %w", err)
	}

	user.FirstName = firstName.String
	user.LastName = lastName.String
	user.UpdatedAt = user.CreatedAt

	return &user, nil
}

func (r *authRepository) FindUserByEmail(ctx context.Context, email string) (*domain.User, error) {
	query := `
		SELECT id, username, password_hash, email, first_name, last_name, 
		       is_active, is_verified, created_at
		FROM users 
		WHERE email = ?`

	var user domain.User
	var firstName, lastName sql.NullString

	err := r.db.QueryRowContext(ctx, query, email).Scan(
		&user.ID,
		&user.UserName,
		&user.Password,
		&user.Email,
		&firstName,
		&lastName,
		&user.IsActive,
		&user.IsVerified,
		&user.CreatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("user not found")
		}
		return nil, fmt.Errorf("failed to find user by email: %w", err)
	}

	user.FirstName = firstName.String
	user.LastName = lastName.String
	user.UpdatedAt = user.CreatedAt

	return &user, nil
}

func (r *authRepository) CreateUser(ctx context.Context, user *domain.UserWithRole) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Insert user
	insertUserQuery := `
		INSERT INTO users (id, username, password_hash, email, first_name, last_name, 
		                  is_active, is_verified, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`

	_, err = tx.ExecContext(ctx, insertUserQuery,
		user.User.ID,
		user.User.UserName,
		user.User.Password,
		user.User.Email,
		nullString(user.User.FirstName),
		nullString(user.User.LastName),
		user.User.IsActive,
		user.User.IsVerified,
		time.Now(),
	)

	if err != nil {
		return fmt.Errorf("failed to insert user: %w", err)
	}

	// Insert user role
	insertUserRoleQuery := `
		INSERT INTO user_roles (user_id, role_id) 
		VALUES (?, ?)`

	_, err = tx.ExecContext(ctx, insertUserRoleQuery, user.User.ID, user.RoleID)
	if err != nil {
		return fmt.Errorf("failed to insert user role: %w", err)
	}

	return tx.Commit()
}

func (r *authRepository) IsEmailExists(ctx context.Context, email string) (int, error) {
	query := `SELECT COUNT(*) FROM users WHERE email = ?`

	var count int
	err := r.db.QueryRowContext(ctx, query, email).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to check email exists: %w", err)
	}

	return count, nil
}

func (r *authRepository) IsUsernameExists(ctx context.Context, username string) (int, error) {
	query := `SELECT COUNT(*) FROM users WHERE username = ?`

	var count int
	err := r.db.QueryRowContext(ctx, query, username).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to check username exists: %w", err)
	}

	return count, nil
}

// Role operations
func (r *authRepository) FindRoleByName(ctx context.Context, roleName string) (*domain.Role, error) {
	query := `SELECT id, name FROM roles WHERE name = ?`

	var role domain.Role
	err := r.db.QueryRowContext(ctx, query, roleName).Scan(&role.ID, &role.Name)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("role not found")
		}
		return nil, fmt.Errorf("failed to find role by name: %w", err)
	}

	return &role, nil
}

func (r *authRepository) GetDefaultRole(ctx context.Context) (*domain.Role, error) {
	return r.FindRoleByName(ctx, "USER")
}

// OAuth2 Client operations
func (r *authRepository) FindClientByID(ctx context.Context, clientID string) (*domain.Client, error) {
	query := `
		SELECT id, client_secret_hash, client_name, redirect_uris, 
		       allowed_grant_types, owner_user_id
		FROM clients 
		WHERE id = ?`

	var client domain.Client
	err := r.db.QueryRowContext(ctx, query, clientID).Scan(
		&client.ClientID,
		&client.ClientSecretHash,
		&client.ClientName,
		&client.RedirectURI,
		&client.AllowedGrantTypes,
		&client.ClientID, // owner_user_id - placeholder
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("client not found")
		}
		return nil, fmt.Errorf("failed to find client by ID: %w", err)
	}

	return &client, nil
}

func (r *authRepository) ValidateClientCredentials(ctx context.Context, clientID, clientSecret string) (*domain.Client, error) {
	client, err := r.FindClientByID(ctx, clientID)
	if err != nil {
		return nil, err
	}

	// In production, you should hash the clientSecret and compare with stored hash
	// For now, simple comparison (implement proper hashing later)
	if client.ClientSecretHash != clientSecret {
		return nil, fmt.Errorf("invalid client credentials")
	}

	return client, nil
}

// Authorization Code operations
func (r *authRepository) CreateAuthorizationCode(ctx context.Context, code *domain.AuthorizationCode) error {
	query := `
		INSERT INTO authorization_codes (code, user_id, client_id, scopes, redirect_uri, 
		                               code_challenge, code_challenge_method, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`

	_, err := r.db.ExecContext(ctx, query,
		code.Code,
		code.UserID,
		code.ClientID,
		code.Scopes,
		code.RedirectURI,
		nullString(code.CodeChallenge),
		nullString(code.CodeChallengeMethod),
		code.ExpiresAt,
	)

	if err != nil {
		return fmt.Errorf("failed to create authorization code: %w", err)
	}

	return nil
}

func (r *authRepository) FindAuthorizationCode(ctx context.Context, code string) (*domain.AuthorizationCode, error) {
	query := `
		SELECT code, user_id, client_id, scopes, redirect_uri, 
		       code_challenge, code_challenge_method, expires_at
		FROM authorization_codes 
		WHERE code = ?`

	var authCode domain.AuthorizationCode
	var codeChallenge, codeChallengeMethod sql.NullString

	err := r.db.QueryRowContext(ctx, query, code).Scan(
		&authCode.Code,
		&authCode.UserID,
		&authCode.ClientID,
		&authCode.Scopes,
		&authCode.RedirectURI,
		&codeChallenge,
		&codeChallengeMethod,
		&authCode.ExpiresAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("authorization code not found")
		}
		return nil, fmt.Errorf("failed to find authorization code: %w", err)
	}

	authCode.CodeChallenge = codeChallenge.String
	authCode.CodeChallengeMethod = codeChallengeMethod.String
	authCode.Used = false // We delete instead of marking as used

	return &authCode, nil
}

func (r *authRepository) DeleteAuthorizationCode(ctx context.Context, code string) error {
	query := `DELETE FROM authorization_codes WHERE code = ?`

	_, err := r.db.ExecContext(ctx, query, code)
	if err != nil {
		return fmt.Errorf("failed to delete authorization code: %w", err)
	}

	return nil
}

// Access Token operations
func (r *authRepository) StoreAccessToken(ctx context.Context, token *domain.AccessToken) error {
	query := `
		INSERT INTO access_tokens (token_hash, user_id, client_id, scopes, expires_at)
		VALUES (?, ?, ?, ?, ?)`

	_, err := r.db.ExecContext(ctx, query,
		token.ID,
		token.UserID,
		token.ClientID,
		token.Scopes,
		token.ExpiresAt,
	)

	if err != nil {
		return fmt.Errorf("failed to store access token: %w", err)
	}

	return nil
}

func (r *authRepository) FindAccessToken(ctx context.Context, tokenID string) (*domain.AccessToken, error) {
	query := `
		SELECT token_hash, user_id, client_id, scopes, expires_at
		FROM access_tokens 
		WHERE token_hash = ?`

	var token domain.AccessToken
	err := r.db.QueryRowContext(ctx, query, tokenID).Scan(
		&token.ID,
		&token.UserID,
		&token.ClientID,
		&token.Scopes,
		&token.ExpiresAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("access token not found")
		}
		return nil, fmt.Errorf("failed to find access token: %w", err)
	}

	return &token, nil
}

func (r *authRepository) RevokeAccessToken(ctx context.Context, tokenID string) error {
	query := `DELETE FROM access_tokens WHERE token_hash = ?`

	_, err := r.db.ExecContext(ctx, query, tokenID)
	if err != nil {
		return fmt.Errorf("failed to revoke access token: %w", err)
	}

	return nil
}

// Refresh Token operations
func (r *authRepository) StoreRefreshToken(ctx context.Context, token *domain.RefreshToken) error {
	query := `
		INSERT INTO refresh_tokens (token_hash, user_id, client_id, scopes, is_revoked, expires_at)
		VALUES (?, ?, ?, ?, ?, ?)`

	tokenID := generateTokenID() // Generate a unique ID for the refresh token

	_, err := r.db.ExecContext(ctx, query,
		tokenID,
		token.UserID,
		token.ClientID,
		token.Scopes,
		token.IsRevoked,
		token.ExpiresAt,
	)

	if err != nil {
		return fmt.Errorf("failed to store refresh token: %w", err)
	}

	return nil
}

func (r *authRepository) FindRefreshToken(ctx context.Context, tokenID string) (*domain.RefreshToken, error) {
	query := `
		SELECT token_hash, user_id, client_id, scopes, is_revoked, expires_at
		FROM refresh_tokens 
		WHERE token_hash = ? AND is_revoked = 0`

	var token domain.RefreshToken
	var id string
	err := r.db.QueryRowContext(ctx, query, tokenID).Scan(
		&id,
		&token.UserID,
		&token.ClientID,
		&token.Scopes,
		&token.IsRevoked,
		&token.ExpiresAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("refresh token not found or revoked")
		}
		return nil, fmt.Errorf("failed to find refresh token: %w", err)
	}

	return &token, nil
}

func (r *authRepository) RevokeRefreshToken(ctx context.Context, tokenID string) error {
	query := `UPDATE refresh_tokens SET is_revoked = 1 WHERE token_hash = ?`

	_, err := r.db.ExecContext(ctx, query, tokenID)
	if err != nil {
		return fmt.Errorf("failed to revoke refresh token: %w", err)
	}

	return nil
}

func (r *authRepository) RevokeAllUserTokens(ctx context.Context, userID string) error {
	query := `UPDATE refresh_tokens SET is_revoked = 1 WHERE user_id = ?`

	_, err := r.db.ExecContext(ctx, query, userID)
	if err != nil {
		return fmt.Errorf("failed to revoke all user tokens: %w", err)
	}

	return nil
}

// User Consent operations
func (r *authRepository) CreateUserConsent(ctx context.Context, consent *domain.UserConsent) error {
	query := `
		INSERT INTO user_consents (user_id, client_id, scopes_granted) 
		VALUES (?, ?, ?)
		ON DUPLICATE KEY UPDATE scopes_granted = VALUES(scopes_granted)`

	_, err := r.db.ExecContext(ctx, query,
		consent.UserID,
		consent.ClientID,
		consent.ScopesGranted,
	)

	if err != nil {
		return fmt.Errorf("failed to create user consent: %w", err)
	}

	return nil
}

func (r *authRepository) FindUserConsent(ctx context.Context, userID, clientID string) (*domain.UserConsent, error) {
	query := `
		SELECT user_id, client_id, scopes_granted
		FROM user_consents 
		WHERE user_id = ? AND client_id = ?`

	var consent domain.UserConsent
	err := r.db.QueryRowContext(ctx, query, userID, clientID).Scan(
		&consent.UserID,
		&consent.ClientID,
		&consent.ScopesGranted,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("user consent not found")
		}
		return nil, fmt.Errorf("failed to find user consent: %w", err)
	}

	return &consent, nil
}

// Helper functions
func nullString(s string) sql.NullString {
	if s == "" {
		return sql.NullString{Valid: false}
	}
	return sql.NullString{String: s, Valid: true}
}

// User Session operations (for cookie-based auth)
func (r *authRepository) StoreUserSession(ctx context.Context, session *domain.UserSession) error {
	query := `
		INSERT INTO user_sessions (session_token, user_id, client_id, expires_at, is_active, created_at)
		VALUES (?, ?, ?, ?, ?, ?)`

	_, err := r.db.ExecContext(ctx, query,
		session.SessionToken,
		session.UserID,
		session.ClientID,
		session.ExpiresAt,
		session.IsActive,
		time.Now(),
	)

	if err != nil {
		return fmt.Errorf("failed to store user session: %w", err)
	}

	return nil
}

func (r *authRepository) FindUserSession(ctx context.Context, sessionToken string) (*domain.UserSession, error) {
	query := `
		SELECT session_token, user_id, client_id, expires_at, is_active, created_at
		FROM user_sessions 
		WHERE session_token = ? AND is_active = 1`

	var session domain.UserSession
	err := r.db.QueryRowContext(ctx, query, sessionToken).Scan(
		&session.SessionToken,
		&session.UserID,
		&session.ClientID,
		&session.ExpiresAt,
		&session.IsActive,
		&session.CreatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("session not found")
		}
		return nil, fmt.Errorf("failed to find user session: %w", err)
	}

	// Check if session is expired
	if session.ExpiresAt.Before(time.Now()) {
		// Auto-expire the session
		r.InvalidateUserSession(ctx, sessionToken)
		return nil, fmt.Errorf("session expired")
	}

	return &session, nil
}

func (r *authRepository) InvalidateUserSession(ctx context.Context, sessionToken string) error {
	query := `UPDATE user_sessions SET is_active = 0 WHERE session_token = ?`

	_, err := r.db.ExecContext(ctx, query, sessionToken)
	if err != nil {
		return fmt.Errorf("failed to invalidate user session: %w", err)
	}

	return nil
}

func (r *authRepository) RevokeAllUserSessions(ctx context.Context, userID string) error {
	query := `UPDATE user_sessions SET is_active = 0 WHERE user_id = ?`

	_, err := r.db.ExecContext(ctx, query, userID)
	if err != nil {
		return fmt.Errorf("failed to revoke all user sessions: %w", err)
	}

	return nil
}

func generateTokenID() string {
	return fmt.Sprintf("token_%d", time.Now().UnixNano())
}
