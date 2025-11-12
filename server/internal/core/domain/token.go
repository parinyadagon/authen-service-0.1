package domain

import "time"

type RefreshToken struct {
	TokenHash string    `json:"token_hash"`
	UserID    string    `json:"user_id"`
	ClientID  string    `json:"client_id"`
	Scopes    string    `json:"scopes"`
	IsRevoked bool      `json:"is_revoked"`
	ExpiresAt time.Time `json:"expires_at"`
}

type AccessToken struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	ClientID  string    `json:"client_id"`
	Scopes    string    `json:"scopes"`
	ExpiresAt time.Time `json:"expires_at"`
}
