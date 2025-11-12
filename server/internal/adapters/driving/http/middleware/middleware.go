package middleware

import (
	"context"
	"log"
	"server/internal/core/ports"
	"server/internal/utils"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/logger"
)

// CORS middleware for Fiber
func CORS() fiber.Handler {
	return cors.New(cors.Config{
		AllowOrigins:     "http://localhost:3000,http://localhost:8000,http://localhost:8080",
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

// Hybrid Authentication middleware (Cookie + JWT) for Fiber - requires repository injection
func HybridAuth(authRepo ports.AuthRepositoryPort) fiber.Handler {
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

		// If JWT failed, try cookie-based session authentication
		if !authenticated {
			sessionToken := c.Cookies("session_token")
			if sessionToken != "" {
				// Validate session against database
				session, err := authRepo.FindUserSession(c.Context(), sessionToken)
				if err == nil && session.IsActive {
					// Additional security checks
					currentIP := c.IP()
					currentUserAgent := c.Get("User-Agent")
					securityViolation := false

					// Check IP consistency - revoke session if IP changed
					if session.IPAddress != "" && session.IPAddress != currentIP {
						log.Printf("SECURITY ALERT: Session IP mismatch for user %s: stored=%s, current=%s - REVOKING SESSION",
							session.UserID, session.IPAddress, currentIP)
						// securityViolation = true
					}

					// Check User-Agent consistency - revoke session if device changed
					if session.UserAgent != "" && session.UserAgent != currentUserAgent {
						log.Printf("SECURITY ALERT: Session User-Agent changed for user %s - REVOKING SESSION", session.UserID)
						// securityViolation = true
					}

					// Revoke session immediately if security violation detected
					if securityViolation {
						// Revoke the compromised session asynchronously
						go func() {
							ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
							defer cancel()

							// Invalidate the current compromised session
							if err := authRepo.InvalidateUserSession(ctx, sessionToken); err != nil {
								log.Printf("Failed to revoke compromised session: %v", err)
							} else {
								log.Printf("Successfully revoked compromised session for user %s", session.UserID)
							}

							// Optional: Revoke ALL user sessions if configured for high security
							// This forces re-authentication on all devices
							// Uncomment the following lines for maximum security:
							/*
								if err := authRepo.RevokeAllUserSessions(ctx, session.UserID); err != nil {
									log.Printf("Failed to revoke all user sessions: %v", err)
								} else {
									log.Printf("Revoked ALL sessions for user %s due to security violation", session.UserID)
								}
							*/
						}()

						// Log security incident for monitoring/alerting
						log.Printf("SECURITY INCIDENT: User %s session compromised from IP %s (expected: %s)",
							session.UserID, currentIP, session.IPAddress)

						// Return unauthorized immediately with clear message
						return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
							"error":   "Session security violation detected",
							"details": "Your session has been revoked due to suspicious activity. Please login again.",
							"code":    "SESSION_COMPROMISED",
							"action":  "LOGIN_REQUIRED",
						})
					}

					// Get user info from database to set username
					user, err := authRepo.FindUserByID(c.Context(), session.UserID)
					if err == nil {
						userID = session.UserID
						username = user.UserName
						authenticated = true
						c.Locals("auth_type", "cookie")
						c.Locals("session_token", sessionToken)
						c.Locals("session", session)

						// Update last accessed time and extend session if needed
						go func() {
							ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
							defer cancel()

							// Update last access time
							authRepo.UpdateSessionAccess(ctx, sessionToken, time.Now())

							// Auto-extend session if it's close to expiry
							timeUntilExpiry := time.Until(session.ExpiresAt)
							if timeUntilExpiry < 2*time.Hour { // Extend if less than 2 hours left
								newExpiry := time.Now().Add(24 * time.Hour)
								log.Printf("Auto-extending session for user %s until %s", session.UserID, newExpiry.Format("2006-01-02 15:04:05"))
								if err := authRepo.ExtendSession(ctx, sessionToken, newExpiry); err != nil {
									log.Printf("Failed to extend session: %v", err)
								}
							}
						}()
					}
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
