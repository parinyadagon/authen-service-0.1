package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"server/internal/adapters/driven/mysql"
	"server/internal/adapters/driving/http/handlers"
	"server/internal/adapters/driving/http/routes"
	"server/internal/config"
	"server/internal/core/service"
)

func main() {
	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	log.Printf("Starting Authentication Service in %s mode", cfg.Environment)

	// Database configuration
	dbConfig := &mysql.Config{
		Host:         cfg.Database.Host,
		Port:         cfg.Database.Port,
		Username:     cfg.Database.Username,
		Password:     cfg.Database.Password,
		Database:     cfg.Database.Database,
		MaxOpenConns: cfg.Database.MaxOpenConns,
		MaxIdleConns: cfg.Database.MaxIdleConns,
		MaxLifetime:  cfg.Database.MaxLifetime,
	}

	// Connect to database
	db, err := mysql.NewConnection(dbConfig)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()

	log.Println("Database connection established")

	// Initialize repository
	authRepo := mysql.NewAuthRepository(db)

	// Initialize service
	authService := service.NewAuthService(authRepo)

	// Initialize handlers
	authHandler := handlers.NewAuthHandler(authService)

	// Setup routes
	router := routes.SetupRoutes(authHandler)

	// Create HTTP server
	server := &http.Server{
		Addr:           cfg.GetServerAddress(),
		Handler:        router,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20, // 1MB
	}

	// Start server in a goroutine
	go func() {
		log.Printf("Server starting on %s", cfg.GetServerAddress())
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server failed to start: %v", err)
		}
	}()

	// Test database connection with a simple query
	ctx := context.Background()
	count, err := authRepo.IsEmailExists(ctx, "test@example.com")
	if err != nil {
		log.Printf("Warning: Database test query failed: %v", err)
	} else {
		log.Printf("Database test successful - email check count: %d", count)
	}

	log.Println("Authentication Service started successfully!")
	log.Printf("API Documentation: http://%s/", cfg.GetServerAddress())
	log.Printf("Health Check: http://%s/health", cfg.GetServerAddress())

	// Wait for interrupt signal to gracefully shutdown the server
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Server shutting down...")

	// Graceful shutdown with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		log.Printf("Server forced to shutdown: %v", err)
	}

	log.Println("Server exited")
}
