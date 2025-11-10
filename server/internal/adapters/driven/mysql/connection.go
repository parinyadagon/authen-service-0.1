package mysql

import (
	"database/sql"
	"fmt"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

type Config struct {
	Host         string
	Port         int
	Username     string
	Password     string
	Database     string
	MaxOpenConns int
	MaxIdleConns int
	MaxLifetime  time.Duration
}

func NewConnection(config *Config) (*sql.DB, error) {
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?charset=utf8mb4&parseTime=True&loc=Local",
		config.Username,
		config.Password,
		config.Host,
		config.Port,
		config.Database,
	)

	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open database connection: %w", err)
	}

	// Configure connection pool
	if config.MaxOpenConns > 0 {
		db.SetMaxOpenConns(config.MaxOpenConns)
	} else {
		db.SetMaxOpenConns(25) // Default
	}

	if config.MaxIdleConns > 0 {
		db.SetMaxIdleConns(config.MaxIdleConns)
	} else {
		db.SetMaxIdleConns(25) // Default
	}

	if config.MaxLifetime > 0 {
		db.SetConnMaxLifetime(config.MaxLifetime)
	} else {
		db.SetConnMaxLifetime(5 * time.Minute) // Default
	}

	// Test the connection
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	return db, nil
}

func DefaultConfig() *Config {
	return &Config{
		Host:         "localhost",
		Port:         3306,
		Username:     "root",
		Password:     "password",
		Database:     "authen_db",
		MaxOpenConns: 25,
		MaxIdleConns: 25,
		MaxLifetime:  5 * time.Minute,
	}
}
