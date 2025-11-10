package middleware

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"server/internal/utils"

	"github.com/gin-gonic/gin"
)

// CORS middleware
func CORS() gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		origin := c.Request.Header.Get("Origin")

		// Allow specific origins in production
		allowedOrigins := []string{
			"http://localhost:3000",
			"http://localhost:3001",
			"http://localhost:8080",
		}

		// Check if origin is allowed
		allowed := false
		for _, allowedOrigin := range allowedOrigins {
			if origin == allowedOrigin {
				allowed = true
				break
			}
		}

		if allowed {
			c.Header("Access-Control-Allow-Origin", origin)
		}

		c.Header("Access-Control-Allow-Credentials", "true")
		c.Header("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With, X-User-ID")
		c.Header("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE, UPDATE")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	})
}

// RequestLogger middleware
func RequestLogger() gin.HandlerFunc {
	return gin.LoggerWithFormatter(func(param gin.LogFormatterParams) string {
		return fmt.Sprintf("%s - [%s] \"%s %s %s %d %s \"%s\" %s\"\n",
			param.ClientIP,
			param.TimeStamp.Format(time.RFC1123),
			param.Method,
			param.Path,
			param.Request.Proto,
			param.StatusCode,
			param.Latency,
			param.Request.UserAgent(),
			param.ErrorMessage,
		)
	})
}

// JWT Authentication middleware
func JWTAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Authorization header required",
			})
			c.Abort()
			return
		}

		// Bearer token format
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Invalid authorization header format",
			})
			c.Abort()
			return
		}

		token := parts[1]
		claims, err := utils.ValidateAccessToken(token)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "Invalid access token",
				"details": err.Error(),
			})
			c.Abort()
			return
		}

		// Set user info in context
		c.Set("user_id", claims.UserID)
		c.Set("username", claims.UserName)
		c.Set("claims", claims)

		c.Next()
	}
}

// Rate limiting middleware (simple in-memory implementation)
func RateLimit() gin.HandlerFunc {
	// This is a simple implementation
	// In production, use Redis or proper rate limiting library
	return func(c *gin.Context) {
		// Skip rate limiting for now
		c.Next()
	}
}

// Security headers middleware
func SecurityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		c.Header("X-XSS-Protection", "1; mode=block")
		c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		c.Header("Content-Security-Policy", "default-src 'self'")
		c.Next()
	}
}

// Hybrid Authentication middleware (Cookie + JWT)
func HybridAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		var userID, username string
		authenticated := false

		// Try JWT authentication first
		authHeader := c.GetHeader("Authorization")
		if authHeader != "" {
			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) == 2 && parts[0] == "Bearer" {
				token := parts[1]
				claims, err := utils.ValidateAccessToken(token)
				if err == nil {
					userID = claims.UserID
					username = claims.UserName
					authenticated = true
					c.Set("auth_type", "jwt")
				}
			}
		}

		// If JWT failed, try cookie authentication
		if !authenticated {
			sessionToken, err := c.Cookie("session_token")
			if err == nil && sessionToken != "" {
				// Validate session token (you'd implement session validation)
				// For now, we'll use a simple approach
				claims, err := utils.ValidateSessionToken(sessionToken)
				if err == nil {
					userID = claims.UserID
					username = claims.UserName
					authenticated = true
					c.Set("auth_type", "cookie")
				}
			}
		}

		if !authenticated {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Authentication required",
				"hint":  "Provide either Bearer token or valid session cookie",
			})
			c.Abort()
			return
		}

		// Set user context
		c.Set("user_id", userID)
		c.Set("username", username)
		c.Next()
	}
}
