package utils

import (
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"
)

type TokenConfig struct {
	SecretKey            []byte
	AccessTokenDuration  time.Duration
	RefreshTokenDuration time.Duration
}

func NewTokenConfig() *TokenConfig {
	if err := godotenv.Load(); err != nil {
		// .env file is optional
		fmt.Println("Warning: .env file not found, using environment variables")
	}

	secretKey := os.Getenv("JWT_SECRET_KEY")
	if secretKey == "" {
		log.Fatal("JWT_SECRET_KEY environment variable is required")
	}

	return &TokenConfig{
		SecretKey:            []byte(secretKey),
		AccessTokenDuration:  15 * time.Minute,
		RefreshTokenDuration: 7 * 24 * time.Hour,
	}
}

type Claims struct {
	UserID   string `json:"user_id"`
	UserName string `json:"user_name"`
	jwt.RegisteredClaims
}

type RefreshClaims struct {
	UserID string `json:"user_id"`
	jwt.RegisteredClaims
}

func (tc *TokenConfig) GenerateAccessToken(userID, username string) (string, error) {
	if userID == "" || username == "" {
		return "", errors.New("userID and username cannot be empty")
	}

	claims := Claims{
		UserID:   userID,
		UserName: username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(tc.AccessTokenDuration)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Subject:   userID,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenString, err := token.SignedString(tc.SecretKey)
	if err != nil {
		return "", fmt.Errorf("error signing access token: %w", err)
	}

	return tokenString, nil
}

func (tc *TokenConfig) GenerateRefreshToken(userID string) (string, error) {
	if userID == "" {
		return "", errors.New("userID cannot be empty")
	}

	claims := RefreshClaims{
		UserID: userID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(tc.RefreshTokenDuration)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Subject:   userID,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(tc.SecretKey)
	if err != nil {
		return "", fmt.Errorf("error singing refresh token: %w", err)
	}

	return tokenString, nil
}

func (tc *TokenConfig) ValidateAccessToken(tokenString string) (*Claims, error) {
	if tokenString == "" {
		return nil, errors.New("token cannot be empty")
	}

	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}

		return tc.SecretKey, nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return claims, nil
	}

	return nil, errors.New("invalid token")
}

func (tc *TokenConfig) ValidateRefreshToken(tokenString string) (string, error) {
	if tokenString == "" {
		return "", errors.New("token cannot be empty")
	}
	token, err := jwt.ParseWithClaims(tokenString, &RefreshClaims{}, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return tc.SecretKey, nil
	})
	if err != nil {
		return "", fmt.Errorf("failed to parse refresh token: %w", err)
	}

	if claims, ok := token.Claims.(*RefreshClaims); ok && token.Valid {
		return claims.UserID, nil
	}

	return "", errors.New("invalid refresh token")
}

var defaultConfig = NewTokenConfig()

func GenerateAccessToken(userID, username string) (string, error) {
	return defaultConfig.GenerateAccessToken(userID, username)
}

func GenerateRefreshToken(userID string) (string, error) {
	return defaultConfig.GenerateRefreshToken(userID)
}

func ValidateAccessToken(tokenString string) (*Claims, error) {
	return defaultConfig.ValidateAccessToken(tokenString)
}

func ValidateRefreshToken(tokenString string) (string, error) {
	return defaultConfig.ValidateRefreshToken(tokenString)
}

// ValidateSessionToken validates session token (for cookie-based auth)
// For simplicity, we'll use JWT for session tokens too
func ValidateSessionToken(sessionToken string) (*Claims, error) {
	return defaultConfig.ValidateAccessToken(sessionToken)
}
