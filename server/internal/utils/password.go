package utils

import (
	"errors"
	"fmt"

	"github.com/matthewhartstonge/argon2"
)

const MinPasswordLength = 8

type PasswordConfig struct {
	argon argon2.Config
}

func NewPasswordConfig() *PasswordConfig {
	return &PasswordConfig{
		argon: argon2.DefaultConfig(),
	}
}

func (pc *PasswordConfig) HashPassword(password string) (string, error) {
	if err := validatePassword(password); err != nil {
		return "", err
	}

	encoded, err := pc.argon.HashEncoded([]byte(password))
	if err != nil {
		return "", fmt.Errorf("failed to hash password: %w", err)
	}

	return string(encoded), nil
}

func (pc *PasswordConfig) VerifyPassword(passwordHashed, passwordText string) (bool, error) {
	if passwordHashed == "" || passwordText == "" {
		return false, errors.New("password and hash cannot be empty")
	}

	ok, err := argon2.VerifyEncoded([]byte(passwordText), []byte(passwordHashed))
	if err != nil {
		return false, fmt.Errorf("password verification failed: %w", err)
	}

	return ok, nil
}

func HashPassword(password string) (string, error) {
	config := NewPasswordConfig()
	return config.HashPassword(password)
}

func VerifyPassword(passwordHashed, passwordText string) (bool, error) {
	config := NewPasswordConfig()
	return config.VerifyPassword(passwordHashed, passwordText)
}

func validatePassword(password string) error {
	if password == "" {
		return errors.New("password cannot be empty")
	}

	if len(password) < MinPasswordLength {
		return fmt.Errorf("password must be at least %d characters long", MinPasswordLength)
	}

	return nil
}
