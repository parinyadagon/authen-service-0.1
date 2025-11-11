package routes

import (
	"server/internal/adapters/driving/http/handlers"
	"server/internal/adapters/driving/http/middleware"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/recover"
)

func SetupRoutes(authHandler *handlers.AuthHandler) *fiber.App {
	// Create Fiber app
	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			code := fiber.StatusInternalServerError
			if e, ok := err.(*fiber.Error); ok {
				code = e.Code
			}
			return c.Status(code).JSON(fiber.Map{
				"error": err.Error(),
			})
		},
	})

	// Global middleware
	app.Use(middleware.RequestLogger())
	app.Use(middleware.CORS())
	app.Use(middleware.SecurityHeaders())
	app.Use(recover.New())

	// Health check - no auth required
	app.Get("/health", authHandler.Health)

	// API routes
	api := app.Group("/api")

	// Public auth routes - no JWT required
	auth := api.Group("/auth")
	auth.Post("/register", authHandler.Register)
	auth.Post("/login", authHandler.Login)
	auth.Post("/refresh", authHandler.Refresh)
	auth.Post("/logout", authHandler.Logout)

	// Protected routes - JWT or cookie auth required
	protected := api.Group("/")
	protected.Use(middleware.HybridAuth())

	// User profile endpoint example
	protected.Get("/profile", func(c *fiber.Ctx) error {
		userID := c.Locals("user_id").(string)
		username := c.Locals("username").(string)
		authType := c.Locals("auth_type").(string)

		return c.JSON(fiber.Map{
			"user_id":   userID,
			"username":  username,
			"auth_type": authType,
			"message":   "This is a protected endpoint",
		})
	})

	// OAuth2 routes
	oauth := app.Group("/oauth")
	
	// OAuth2 authorization endpoint - requires user authentication
	oauth.Get("/authorize", authHandler.Authorize)
	
	// OAuth2 token endpoint - client authentication
	oauth.Post("/token", authHandler.Token)

	// API documentation endpoint
	app.Get("/", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"service": "Authentication Service",
			"version": "0.1.0",
			"endpoints": fiber.Map{
				"health":          "GET /health",
				"register":        "POST /api/auth/register",
				"login":           "POST /api/auth/login",
				"refresh":         "POST /api/auth/refresh",
				"logout":          "POST /api/auth/logout",
				"profile":         "GET /api/profile (requires auth)",
				"oauth_authorize": "GET /oauth/authorize",
				"oauth_token":     "POST /oauth/token",
			},
			"auth_types": fiber.Map{
				"jwt":    "Bearer token in Authorization header",
				"cookie": "httpOnly session cookies",
			},
			"documentation": "https://github.com/your-repo/authen-service",
		})
	})

	return app
}