package config

import (
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/joho/godotenv"
)

type Config struct {
	// Database
	Database DatabaseConfig

	// JWT
	JWT JWTConfig

	// Server
	Server ServerConfig

	// Environment
	Environment string

	// OAuth2
	OAuth2 OAuth2Config
}

type DatabaseConfig struct {
	Host         string
	Port         int
	Username     string
	Password     string
	Database     string
	MaxOpenConns int
	MaxIdleConns int
	MaxLifetime  time.Duration
}

type JWTConfig struct {
	SecretKey            string
	AccessTokenDuration  time.Duration
	RefreshTokenDuration time.Duration
}

type ServerConfig struct {
	Host string
	Port int
}

type OAuth2Config struct {
	DefaultClientID     string
	DefaultClientSecret string
}

func Load() (*Config, error) {
	// Load .env file if it exists
	if err := godotenv.Load(); err != nil {
		// .env file is optional
		fmt.Println("Warning: .env file not found, using environment variables")
	}

	config := &Config{
		Database: DatabaseConfig{
			Host:         getEnv("DB_HOST", "localhost"),
			Port:         getEnvAsInt("DB_PORT", 3306),
			Username:     getEnv("DB_USERNAME", "root"),
			Password:     getEnv("DB_PASSWORD", "password"),
			Database:     getEnv("DB_NAME", "authen_db"),
			MaxOpenConns: getEnvAsInt("DB_MAX_OPEN_CONNS", 25),
			MaxIdleConns: getEnvAsInt("DB_MAX_IDLE_CONNS", 25),
			MaxLifetime:  getEnvAsDuration("DB_MAX_LIFETIME", 5*time.Minute),
		},
		JWT: JWTConfig{
			SecretKey:            getEnvRequired("JWT_SECRET_KEY"),
			AccessTokenDuration:  getEnvAsDuration("JWT_ACCESS_TOKEN_DURATION", 15*time.Minute),
			RefreshTokenDuration: getEnvAsDuration("JWT_REFRESH_TOKEN_DURATION", 7*24*time.Hour),
		},
		Server: ServerConfig{
			Host: getEnv("SERVER_HOST", "localhost"),
			Port: getEnvAsInt("SERVER_PORT", 8080),
		},
		Environment: getEnv("ENV", "development"),
		OAuth2: OAuth2Config{
			DefaultClientID:     getEnv("OAUTH2_DEFAULT_CLIENT_ID", "web-client"),
			DefaultClientSecret: getEnv("OAUTH2_DEFAULT_CLIENT_SECRET", "default-secret"),
		},
	}

	return config, config.validate()
}

func (c *Config) validate() error {
	if c.JWT.SecretKey == "" {
		return fmt.Errorf("JWT_SECRET_KEY is required")
	}

	if len(c.JWT.SecretKey) < 32 {
		return fmt.Errorf("JWT_SECRET_KEY must be at least 32 characters long")
	}

	if c.Database.Host == "" {
		return fmt.Errorf("DB_HOST is required")
	}

	if c.Database.Username == "" {
		return fmt.Errorf("DB_USERNAME is required")
	}

	if c.Server.Port <= 0 || c.Server.Port > 65535 {
		return fmt.Errorf("SERVER_PORT must be between 1 and 65535")
	}

	return nil
}

func (c *Config) IsDevelopment() bool {
	return c.Environment == "development"
}

func (c *Config) IsProduction() bool {
	return c.Environment == "production"
}

func (c *Config) GetDatabaseConnectionString() string {
	return fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?charset=utf8mb4&parseTime=True&loc=Local",
		c.Database.Username,
		c.Database.Password,
		c.Database.Host,
		c.Database.Port,
		c.Database.Database,
	)
}

func (c *Config) GetServerAddress() string {
	return fmt.Sprintf("%s:%d", c.Server.Host, c.Server.Port)
}

// Helper functions
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvRequired(key string) string {
	value := os.Getenv(key)
	if value == "" {
		panic(fmt.Sprintf("Environment variable %s is required", key))
	}
	return value
}

func getEnvAsInt(key string, defaultValue int) int {
	valueStr := getEnv(key, "")
	if valueStr == "" {
		return defaultValue
	}

	value, err := strconv.Atoi(valueStr)
	if err != nil {
		return defaultValue
	}

	return value
}

func getEnvAsDuration(key string, defaultValue time.Duration) time.Duration {
	valueStr := getEnv(key, "")
	if valueStr == "" {
		return defaultValue
	}

	value, err := time.ParseDuration(valueStr)
	if err != nil {
		return defaultValue
	}

	return value
}
