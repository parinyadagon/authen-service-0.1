package middleware

import (
	"server/internal/utils"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/logger"
)

// CORS middleware for Fiber
func CORS() fiber.Handler {
	return cors.New(cors.Config{
		AllowOrigins:     "http://localhost:3000,http://localhost:3001,http://localhost:8080",
		AllowHeaders:     "Origin, Content-Type, Accept, Authorization, X-Requested-With, X-User-ID",
		AllowMethods:     "GET,POST,HEAD,PUT,DELETE,PATCH,OPTIONS",
		AllowCredentials: true,
	})
}

// Request Logger middleware for Fiber
func RequestLogger() fiber.Handler {
	return logger.New(logger.Config{
		Format: "${time} | ${status} | ${latency} | ${ip} | ${method} | ${path}\n",
	})
}

// JWT Authentication middleware for Fiber
func JWTAuth() fiber.Handler {
	return func(c *fiber.Ctx) error {
		authHeader := c.Get("Authorization")
		if authHeader == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "Authorization header required",
			})
		}

		// Bearer token format
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "Invalid authorization header format",
			})
		}

		token := parts[1]
		claims, err := utils.ValidateAccessToken(token)
		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error":   "Invalid access token",
				"details": err.Error(),
			})
		}

		// Set user info in context
		c.Locals("user_id", claims.UserID)
		c.Locals("username", claims.UserName)
		c.Locals("claims", claims)

		return c.Next()
	}
}

// Security headers middleware for Fiber
func SecurityHeaders() fiber.Handler {
	return func(c *fiber.Ctx) error {
		c.Set("X-Content-Type-Options", "nosniff")
		c.Set("X-Frame-Options", "DENY")
		c.Set("X-XSS-Protection", "1; mode=block")
		c.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		c.Set("Content-Security-Policy", "default-src 'self'")
		return c.Next()
	}
}

// Hybrid Authentication middleware (Cookie + JWT) for Fiber
func HybridAuth() fiber.Handler {
	return func(c *fiber.Ctx) error {
		var userID, username string
		authenticated := false

		// Try JWT authentication first
		authHeader := c.Get("Authorization")
		if authHeader != "" {
			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) == 2 && parts[0] == "Bearer" {
				token := parts[1]
				claims, err := utils.ValidateAccessToken(token)
				if err == nil {
					userID = claims.UserID
					username = claims.UserName
					authenticated = true
					c.Locals("auth_type", "jwt")
				}
			}
		}

		// If JWT failed, try cookie authentication
		if !authenticated {
			sessionToken := c.Cookies("session_token")
			if sessionToken != "" {
				// For session token, we need access to the repository
				// For now, we'll use a simple JWT validation
				// In production, you'd validate against the session store
				claims, err := utils.ValidateSessionToken(sessionToken)
				if err == nil {
					userID = claims.UserID
					username = claims.UserName
					authenticated = true
					c.Locals("auth_type", "cookie")
				}
			}
		}

		if !authenticated {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "Authentication required",
				"hint":  "Provide either Bearer token or valid session cookie",
			})
		}

		// Set user context
		c.Locals("user_id", userID)
		c.Locals("username", username)
		return c.Next()
	}
}
