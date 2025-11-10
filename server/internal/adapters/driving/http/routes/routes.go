package routes

import (
	"server/internal/adapters/driving/http/handlers"
	"server/internal/adapters/driving/http/middleware"

	"github.com/gin-gonic/gin"
)

func SetupRoutes(authHandler *handlers.AuthHandler) *gin.Engine {
	// Set Gin mode based on environment
	gin.SetMode(gin.ReleaseMode) // Change to gin.DebugMode for development

	router := gin.New()

	// Global middleware
	router.Use(middleware.RequestLogger())
	router.Use(middleware.CORS())
	router.Use(middleware.SecurityHeaders())
	router.Use(middleware.RateLimit())
	router.Use(gin.Recovery())

	// Health check - no auth required
	router.GET("/health", authHandler.Health)

	// API routes
	api := router.Group("/api")
	{
		// Public auth routes - no JWT required
		auth := api.Group("/auth")
		{
			auth.POST("/register", authHandler.Register)
			auth.POST("/login", authHandler.Login)
			auth.POST("/refresh", authHandler.Refresh)
		}

		// Protected routes - JWT required
		protected := api.Group("/")
		protected.Use(middleware.JWTAuth())
		{
			// User profile endpoint example
			protected.GET("/profile", func(c *gin.Context) {
				userID := c.GetString("user_id")
				username := c.GetString("username")

				c.JSON(200, gin.H{
					"user_id":  userID,
					"username": username,
					"message":  "This is a protected endpoint",
				})
			})
		}
	}

	// OAuth2 routes
	oauth := router.Group("/oauth")
	{
		// OAuth2 authorization endpoint - requires user authentication
		oauth.GET("/authorize", authHandler.Authorize)

		// OAuth2 token endpoint - client authentication
		oauth.POST("/token", authHandler.Token)
	}

	// API documentation endpoint
	router.GET("/", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"service": "Authentication Service",
			"version": "0.1.0",
			"endpoints": gin.H{
				"health":          "GET /health",
				"register":        "POST /api/auth/register",
				"login":           "POST /api/auth/login",
				"refresh":         "POST /api/auth/refresh",
				"profile":         "GET /api/profile (requires JWT)",
				"oauth_authorize": "GET /oauth/authorize",
				"oauth_token":     "POST /oauth/token",
			},
			"documentation": "https://github.com/your-repo/authen-service",
		})
	})

	return router
}
