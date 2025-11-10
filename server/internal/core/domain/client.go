package domain

import "time"

type Client struct {
	ClientID          string     `json:"client_id"`
	ClientSecretHash  string     `json:"client_secret_hash"`
	ClientName        string     `json:"client_name"`
	RedirectURI       string     `json:"redirect_uri"`
	AllowedGrantTypes string     `json:"allowed_grant_types"`
	CreatedAt         *time.Time `json:"created_at"`
	UpdatedAt         *time.Time `json:"updated_at"`
}
