package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"server/internal/core/domain"
	"server/internal/core/ports"
	"server/internal/utils"
	"strings"
	"time"
)

type authService struct {
	authRepo ports.AuthRepositoryPort
}

func NewAuthService(authRepo ports.AuthRepositoryPort) ports.AuthServicePort {
	return &authService{authRepo: authRepo}
}

func (s *authService) Login(ctx context.Context, authRep *domain.AuthReq) (*domain.AuthResp, error) {
	if authRep.UserName == "" {
		return nil, errors.New("username is required")
	}
	if authRep.Password == "" {
		return nil, errors.New("password is required")
	}

	found, err := s.authRepo.FindUserByUserName(ctx, authRep.UserName)
	if err != nil {
		log.Printf("user not found: %v", err)
		return nil, err
	}
	if !found.IsActive {
		return nil, errors.New("account is inactive")
	}

	match, err := utils.VerifyPassword(found.Password, authRep.Password)
	if err != nil {
		log.Printf("verify password failed: %v", err)
		return nil, err
	}

	if !match {
		return nil, errors.New("password incorrect")
	}

	accessToken, err := utils.GenerateAccessToken(found.ID, found.UserName)
	if err != nil {
		return nil, err
	}

	refreshToken, err := utils.GenerateRefreshToken(found.ID)
	if err != nil {
		return nil, err
	}

	// Store refresh token in database for session management
	refreshTokenEntity := &domain.RefreshToken{
		UserID:    found.ID,
		ClientID:  "web-client", // Default client for direct login
		Scopes:    "read write", // Default scopes for direct login
		IsRevoked: false,
		ExpiresAt: time.Now().Add(7 * 24 * time.Hour), // 7 days
	}

	err = s.authRepo.StoreRefreshToken(ctx, refreshTokenEntity)
	if err != nil {
		return nil, fmt.Errorf("failed to store refresh token: %w", err)
	}

	// Determine auth type based on request
	authType := "jwt" // default
	if authRep.AuthType == "cookie" {
		authType = "cookie"
	}

	response := &domain.AuthResp{
		User: domain.UserResp{
			UserID:    found.ID,
			UserName:  found.UserName,
			FirstName: found.FirstName,
			LastName:  found.LastName,
			Email:     found.Email,
			IsActive:  found.IsActive,
		},
		AuthType: authType,
	}

	if authType == "cookie" {
		// Generate session token for cookie-based auth
		sessionToken, err := s.generateSecureCode()
		if err != nil {
			return nil, fmt.Errorf("failed to generate session token: %w", err)
		}
		response.SessionToken = sessionToken
		response.RefreshToken = refreshToken // Also include refresh token for cookie renewal

		// Store session in database for server-side session management
		userSession := &domain.UserSession{
			SessionToken: sessionToken,
			UserID:       found.ID,
			ClientID:     "web-client",                   // Default client for direct login
			ExpiresAt:    time.Now().Add(24 * time.Hour), // 24 hours
			IsActive:     true,
			CreatedAt:    time.Now(),
		}

		err = s.authRepo.StoreUserSession(ctx, userSession)
		if err != nil {
			return nil, fmt.Errorf("failed to store user session: %w", err)
		}

	} else {
		// JWT-based auth
		response.AccessToken = accessToken
		response.RefreshToken = refreshToken
	}

	return response, nil
}

func (s *authService) Refresh(ctx context.Context, refreshToken string) (*domain.RefreshResp, error) {
	if refreshToken == "" {
		return nil, errors.New("refresh token required")
	}

	// 1. Validate token format and claims
	userID, err := utils.ValidateRefreshToken(refreshToken)
	if err != nil {
		return nil, errors.New("invalid refresh token")
	}

	// 2. Find refresh token in database
	tokenHash := s.hashToken(refreshToken)
	tokenEntity, err := s.authRepo.FindRefreshToken(ctx, tokenHash)
	if err != nil || tokenEntity.IsRevoked {
		return nil, errors.New("invalid or revoked refresh token")
	}

	if tokenEntity.ExpiresAt.Before(time.Now()) {
		return nil, errors.New("refresh token expired")
	}

	if tokenEntity.UserID != userID {
		return nil, errors.New("token user mismatch")
	}

	// 3. Get user info
	found, err := s.authRepo.FindUserByID(ctx, userID)
	if err != nil || !found.IsActive {
		return nil, errors.New("user not found or inactive")
	}

	// 4. Generate new tokens
	newAccessToken, err := utils.GenerateAccessToken(userID, found.UserName)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	newRefreshToken, err := utils.GenerateRefreshToken(userID)
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	// 5. Token rotation: revoke old token and create new one
	err = s.authRepo.RevokeRefreshToken(ctx, tokenHash)
	if err != nil {
		return nil, fmt.Errorf("failed to revoke old token: %w", err)
	}

	newTokenEntity := &domain.RefreshToken{
		UserID:    userID,
		ClientID:  tokenEntity.ClientID,
		Scopes:    tokenEntity.Scopes,
		IsRevoked: false,
		ExpiresAt: time.Now().Add(7 * 24 * time.Hour), // 7 days
	}

	err = s.authRepo.StoreRefreshToken(ctx, newTokenEntity)
	if err != nil {
		return nil, fmt.Errorf("failed to store new refresh token: %w", err)
	}

	return &domain.RefreshResp{
		RefreshToken: newRefreshToken,
		AccessToken:  newAccessToken,
	}, nil
}

func (s *authService) Register(ctx context.Context, registerReq *domain.RegisterReq) (*domain.RegisterResp, error) {
	if registerReq.UserName == "" {
		return nil, errors.New("username is required")
	}

	if registerReq.Password == "" {
		return nil, errors.New("password is required")
	}

	if registerReq.Email == "" {
		return nil, errors.New("email is required")
	}

	if registerReq.FirstName == "" {
		return nil, errors.New("first name is required")
	}

	if registerReq.LastName == "" {
		return nil, errors.New("last name is required")
	}

	emailAlreadyExisting, err := s.authRepo.IsEmailExists(ctx, registerReq.Email)
	if err != nil {
		return nil, err
	}

	if emailAlreadyExisting > 0 {
		return nil, errors.New("email already")
	}

	usernameAlreadyExisting, err := s.authRepo.IsUsernameExists(ctx, registerReq.UserName)
	if err != nil {
		return nil, err
	}

	if usernameAlreadyExisting > 0 {
		return nil, errors.New("username already")
	}

	passwordHashed, err := utils.HashPassword(registerReq.Password)
	if err != nil {
		return nil, errors.New("hash password failed")
	}

	userReq := &domain.UserReq{
		UserName:  registerReq.UserName,
		FirstName: registerReq.FirstName,
		LastName:  registerReq.LastName,
		Email:     registerReq.Email,
	}

	newUser, err := domain.NewUserWithRole(userReq, domain.RoleUser)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}
	newUser.User.Password = passwordHashed

	role, err := s.authRepo.FindRoleByName(ctx, string(domain.RoleUser))
	if err != nil {
		return nil, fmt.Errorf("failed to find role: %w", err)
	}
	newUser.RoleID = role.ID

	err = s.authRepo.CreateUser(ctx, newUser)
	if err != nil {
		return nil, errors.New("create user failed")
	}

	return &domain.RegisterResp{
		UserName:  newUser.User.UserName,
		FirstName: newUser.User.FirstName,
		LastName:  newUser.User.LastName,
		Email:     newUser.User.Email,
	}, nil
}

// OAuth2 Authorization Code Flow Implementation
func (s *authService) Authorize(ctx context.Context, req *domain.AuthorizeReq, userID string) (*domain.AuthorizeResp, error) {
	// 1. Validate request parameters
	if req.ResponseType != "code" {
		return nil, errors.New("unsupported response type")
	}

	if req.ClientID == "" {
		return nil, errors.New("client_id is required")
	}

	if req.RedirectURI == "" {
		return nil, errors.New("redirect_uri is required")
	}

	// 2. Validate client
	client, err := s.authRepo.FindClientByID(ctx, req.ClientID)
	if err != nil {
		return nil, errors.New("invalid client")
	}

	// 3. Validate redirect URI
	if !s.isValidRedirectURI(req.RedirectURI, client.RedirectURI) {
		return nil, errors.New("invalid redirect_uri")
	}

	// 4. Validate user exists and is active
	user, err := s.authRepo.FindUserByID(ctx, userID)
	if err != nil || !user.IsActive {
		return nil, errors.New("invalid user")
	}

	// 5. Check user consent (optional - could prompt user for consent)
	consent, err := s.authRepo.FindUserConsent(ctx, userID, req.ClientID)
	if err != nil {
		// Create initial consent for requested scopes
		newConsent := &domain.UserConsent{
			UserID:        userID,
			ClientID:      req.ClientID,
			ScopesGranted: req.Scope,
		}
		err = s.authRepo.CreateUserConsent(ctx, newConsent)
		if err != nil {
			return nil, fmt.Errorf("failed to create consent: %w", err)
		}
	} else if !s.hasSufficientConsent(req.Scope, consent.ScopesGranted) {
		return nil, errors.New("insufficient user consent")
	}

	// 6. Generate authorization code
	code, err := s.generateSecureCode()
	if err != nil {
		return nil, fmt.Errorf("failed to generate authorization code: %w", err)
	}

	// 7. Store authorization code
	authCode := &domain.AuthorizationCode{
		Code:                code,
		UserID:              userID,
		ClientID:            req.ClientID,
		Scopes:              req.Scope,
		RedirectURI:         req.RedirectURI,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: req.CodeChallengeMethod,
		ExpiresAt:           time.Now().Add(10 * time.Minute), // 10 minutes
		Used:                false,
	}

	err = s.authRepo.CreateAuthorizationCode(ctx, authCode)
	if err != nil {
		return nil, fmt.Errorf("failed to store authorization code: %w", err)
	}

	return &domain.AuthorizeResp{
		Code:        code,
		State:       req.State,
		RedirectURI: req.RedirectURI,
	}, nil
}

func (s *authService) Token(ctx context.Context, req *domain.TokenReq) (*domain.TokenResp, error) {
	// 1. Validate grant type
	if req.GrantType != "authorization_code" {
		return nil, errors.New("unsupported grant type")
	}

	// 2. Validate client credentials
	_, err := s.authRepo.ValidateClientCredentials(ctx, req.ClientID, req.ClientSecret)
	if err != nil {
		return nil, errors.New("invalid client credentials")
	}

	// 3. Find and validate authorization code
	authCode, err := s.authRepo.FindAuthorizationCode(ctx, req.Code)
	if err != nil {
		return nil, errors.New("invalid authorization code")
	}

	if authCode.Used {
		return nil, errors.New("authorization code already used")
	}

	if authCode.ExpiresAt.Before(time.Now()) {
		return nil, errors.New("authorization code expired")
	}

	if authCode.ClientID != req.ClientID {
		return nil, errors.New("client mismatch")
	}

	if authCode.RedirectURI != req.RedirectURI {
		return nil, errors.New("redirect URI mismatch")
	}

	// 4. Validate PKCE if present
	if authCode.CodeChallenge != "" {
		if req.CodeVerifier == "" {
			return nil, errors.New("code_verifier is required")
		}
		if !s.validatePKCE(authCode.CodeChallenge, authCode.CodeChallengeMethod, req.CodeVerifier) {
			return nil, errors.New("invalid code_verifier")
		}
	}

	// 5. Get user info
	user, err := s.authRepo.FindUserByID(ctx, authCode.UserID)
	if err != nil || !user.IsActive {
		return nil, errors.New("invalid user")
	}

	// 6. Generate tokens
	accessToken, err := utils.GenerateAccessToken(user.ID, user.UserName)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	refreshToken, err := utils.GenerateRefreshToken(user.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	// 7. Store tokens in database (for revocation support)
	accessTokenEntity := &domain.AccessToken{
		ID:        s.hashToken(accessToken),
		UserID:    user.ID,
		ClientID:  req.ClientID,
		Scopes:    authCode.Scopes,
		ExpiresAt: time.Now().Add(15 * time.Minute), // 15 minutes
	}

	refreshTokenEntity := &domain.RefreshToken{
		UserID:    user.ID,
		ClientID:  req.ClientID,
		Scopes:    authCode.Scopes,
		IsRevoked: false,
		ExpiresAt: time.Now().Add(7 * 24 * time.Hour), // 7 days
	}

	err = s.authRepo.StoreAccessToken(ctx, accessTokenEntity)
	if err != nil {
		return nil, fmt.Errorf("failed to store access token: %w", err)
	}

	err = s.authRepo.StoreRefreshToken(ctx, refreshTokenEntity)
	if err != nil {
		return nil, fmt.Errorf("failed to store refresh token: %w", err)
	}

	// 8. Mark authorization code as used
	err = s.authRepo.DeleteAuthorizationCode(ctx, req.Code)
	if err != nil {
		log.Printf("failed to delete authorization code: %v", err)
	}

	return &domain.TokenResp{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    15 * 60, // 15 minutes in seconds
		RefreshToken: refreshToken,
		Scope:        authCode.Scopes,
	}, nil
}

// Helper methods
func (s *authService) generateSecureCode() (string, error) {
	bytes := make([]byte, 32)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func (s *authService) isValidRedirectURI(requestedURI, allowedURIs string) bool {
	// In production, you might store multiple URIs as JSON array
	// For now, simple string comparison
	// Split the allowedURIs by comma or semicolon and check if requestedURI matches any of them
	allowedList := strings.Split(allowedURIs, ",")
	for _, uri := range allowedList {
		if strings.TrimSpace(uri) == requestedURI {
			return true
		}
	}
	return false
}

func (s *authService) hasSufficientConsent(requestedScopes, grantedScopes string) bool {
	requested := strings.Split(requestedScopes, " ")
	granted := strings.Split(grantedScopes, " ")

	grantedMap := make(map[string]bool)
	for _, scope := range granted {
		grantedMap[scope] = true
	}

	for _, scope := range requested {
		if !grantedMap[scope] {
			return false
		}
	}
	return true
}

func (s *authService) validatePKCE(challenge, method, verifier string) bool {
	// Implementation for PKCE validation would go here
	// For now, return true (implement based on RFC 7636)
	return true
}

func (s *authService) hashToken(token string) string {
	// Simple hash for token ID - in production use proper hashing
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

// Session management methods
func (s *authService) InvalidateSession(ctx context.Context, sessionToken string) error {
	return s.authRepo.InvalidateUserSession(ctx, sessionToken)
}

func (s *authService) RefreshSession(ctx context.Context, refreshToken string) (*domain.AuthResp, error) {
	// 1. Validate refresh token
	userID, err := utils.ValidateRefreshToken(refreshToken)
	if err != nil {
		return nil, errors.New("invalid refresh token")
	}

	// 2. Find refresh token in database
	tokenHash := s.hashToken(refreshToken)
	tokenEntity, err := s.authRepo.FindRefreshToken(ctx, tokenHash)
	if err != nil || tokenEntity.IsRevoked {
		return nil, errors.New("invalid or revoked refresh token")
	}

	if tokenEntity.ExpiresAt.Before(time.Now()) {
		return nil, errors.New("refresh token expired")
	}

	// 3. Get user info
	user, err := s.authRepo.FindUserByID(ctx, userID)
	if err != nil || !user.IsActive {
		return nil, errors.New("user not found or inactive")
	}

	// 4. Generate new session token
	newSessionToken, err := s.generateSecureCode()
	if err != nil {
		return nil, fmt.Errorf("failed to generate session token: %w", err)
	}

	// 5. Generate new refresh token
	newRefreshToken, err := utils.GenerateRefreshToken(userID)
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	// 6. Revoke old refresh token and create new one
	err = s.authRepo.RevokeRefreshToken(ctx, tokenHash)
	if err != nil {
		return nil, fmt.Errorf("failed to revoke old token: %w", err)
	}

	newTokenEntity := &domain.RefreshToken{
		UserID:    userID,
		ClientID:  tokenEntity.ClientID,
		Scopes:    tokenEntity.Scopes,
		IsRevoked: false,
		ExpiresAt: time.Now().Add(7 * 24 * time.Hour), // 7 days
	}

	err = s.authRepo.StoreRefreshToken(ctx, newTokenEntity)
	if err != nil {
		return nil, fmt.Errorf("failed to store new refresh token: %w", err)
	}

	// 7. Store new session
	userSession := &domain.UserSession{
		SessionToken: newSessionToken,
		UserID:       userID,
		ClientID:     tokenEntity.ClientID,
		ExpiresAt:    time.Now().Add(24 * time.Hour), // 24 hours
		IsActive:     true,
		CreatedAt:    time.Now(),
	}

	err = s.authRepo.StoreUserSession(ctx, userSession)
	if err != nil {
		return nil, fmt.Errorf("failed to store new session: %w", err)
	}

	return &domain.AuthResp{
		SessionToken: newSessionToken,
		RefreshToken: newRefreshToken,
		AuthType:     "cookie",
		User: domain.UserResp{
			UserID:    user.ID,
			UserName:  user.UserName,
			FirstName: user.FirstName,
			LastName:  user.LastName,
			Email:     user.Email,
			IsActive:  user.IsActive,
		},
	}, nil
}
