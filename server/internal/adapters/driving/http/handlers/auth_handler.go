package handlers

import (
	"context"
	"crypto/sha256"
	"fmt"
	"log"
	"server/internal/core/domain"
	"server/internal/core/ports"

	"github.com/gofiber/fiber/v2"
)

type AuthHandler struct {
	authService ports.AuthServicePort
}

func NewAuthHandler(authService ports.AuthServicePort) *AuthHandler {
	return &AuthHandler{
		authService: authService,
	}
}

// Register handles user registration
// POST /api/auth/register
func (h *AuthHandler) Register(c *fiber.Ctx) error {
	var req domain.RegisterReq
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   "Invalid request format",
			"details": err.Error(),
		})
	}

	resp, err := h.authService.Register(c.Context(), &req)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   "Registration failed",
			"details": err.Error(),
		})
	}

	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
		"message": "User registered successfully",
		"data":    resp,
	})
}

// Login handles user authentication (Hybrid: Cookie + JWT)
// POST /api/auth/login
func (h *AuthHandler) Login(c *fiber.Ctx) error {
	var req domain.AuthReq
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   "Invalid request format",
			"details": err.Error(),
		})
	}

	// Auto-detect auth type if not specified
	if req.AuthType == "" {
		userAgent := c.Get("User-Agent")
		acceptHeader := c.Get("Accept")

		// If request from browser, use cookie
		if userAgent != "" && (acceptHeader == "" || acceptHeader == "text/html" || acceptHeader == "*/*") {
			req.AuthType = "cookie"
		} else {
			req.AuthType = "jwt"
		}
	}

	// Create security context for session management
	ipAddress := c.IP()
	userAgent := c.Get("User-Agent")
	deviceID := c.Get("X-Device-ID")

	// Generate device ID if not provided
	if deviceID == "" {
		// Create a simple device fingerprint based on User-Agent and IP
		deviceID = fmt.Sprintf("auto-%x", sha256.Sum256([]byte(userAgent+ipAddress)))[:16]
	}

	log.Printf("Login attempt - IP: %s, User-Agent: %s, Device-ID: %s", ipAddress, userAgent, deviceID)

	securityCtx := context.WithValue(c.Context(), "ip_address", ipAddress)
	securityCtx = context.WithValue(securityCtx, "user_agent", userAgent)
	securityCtx = context.WithValue(securityCtx, "device_id", deviceID)

	resp, err := h.authService.Login(securityCtx, &req)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error":   "Authentication failed",
			"details": err.Error(),
		})
	}

	// Handle response based on auth type
	if resp.AuthType == "cookie" {
		return h.setCookieAuth(c, resp)
	} else {
		return h.setJWTAuth(c, resp)
	}
}

// Set cookie-based authentication
func (h *AuthHandler) setCookieAuth(c *fiber.Ctx, resp *domain.AuthResp) error {
	// Set secure httpOnly cookies
	c.Cookie(&fiber.Cookie{
		Name:     "session_token",
		Value:    resp.SessionToken,
		MaxAge:   24 * 60 * 60, // 24 hours
		Path:     "/",
		Secure:   true, // HTTPS only in production
		HTTPOnly: true, // XSS protection
		SameSite: "Strict",
	})

	// For cookie-based auth, we don't need refresh token cookies
	// Session renewal is handled automatically by the session management system

	// Return user info only (no sensitive tokens in response body)
	return c.JSON(fiber.Map{
		"message":   "Login successful",
		"auth_type": "cookie",
		"user":      resp.User,
	})
}

// Set JWT-based authentication
func (h *AuthHandler) setJWTAuth(c *fiber.Ctx, resp *domain.AuthResp) error {
	return c.JSON(fiber.Map{
		"message":   "Login successful",
		"auth_type": "jwt",
		"data": fiber.Map{
			"access_token":  resp.AccessToken,
			"refresh_token": resp.RefreshToken,
			"user":          resp.User,
		},
	})
}

// Refresh handles token refresh
// POST /api/auth/refresh
func (h *AuthHandler) Refresh(c *fiber.Ctx) error {
	var req domain.RefreshReq
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   "Invalid request format",
			"details": err.Error(),
		})
	}

	resp, err := h.authService.Refresh(c.Context(), req.RefreshToken)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error":   "Token refresh failed",
			"details": err.Error(),
		})
	}

	return c.JSON(fiber.Map{
		"message": "Token refreshed successfully",
		"data":    resp,
	})
}

// Authorize handles OAuth2 authorization
// GET /oauth/authorize
func (h *AuthHandler) Authorize(c *fiber.Ctx) error {
	var req domain.AuthorizeReq

	// Manual query parsing for debugging
	req.ResponseType = c.Query("response_type")
	req.ClientID = c.Query("client_id")
	req.RedirectURI = c.Query("redirect_uri")
	req.Scope = c.Query("scope")
	req.State = c.Query("state")
	req.CodeChallenge = c.Query("code_challenge")
	req.CodeChallengeMethod = c.Query("code_challenge_method")

	log.Printf("DEBUG: Handler received - ResponseType: '%s', ClientID: '%s'", req.ResponseType, req.ClientID)

	// In a real implementation, you would:
	// 1. Check if user is authenticated (session/cookie)
	// 2. Show consent page if needed
	// 3. Get user consent
	// For now, we'll use a mock user ID
	userID := c.Get("X-User-ID")
	if userID == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error":   "User authentication required",
			"details": "Please login first or provide X-User-ID header for testing",
		})
	}

	resp, err := h.authService.Authorize(c.Context(), &req, userID)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   "Authorization failed",
			"details": err.Error(),
		})
	}

	// In OAuth2, this would typically redirect to client with code
	// For API testing, we return JSON
	return c.JSON(fiber.Map{
		"message": "Authorization successful",
		"data":    resp,
	})
}

// Token handles OAuth2 token exchange
// POST /oauth/token
func (h *AuthHandler) Token(c *fiber.Ctx) error {
	var req domain.TokenReq
	if err := c.BodyParser(&req); err != nil {
		// Try form binding as OAuth2 typically uses form data
		if err := c.QueryParser(&req); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error":   "Invalid request format",
				"details": err.Error(),
			})
		}
	}

	resp, err := h.authService.Token(c.Context(), &req)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   "Token exchange failed",
			"details": err.Error(),
		})
	}

	return c.JSON(resp)
}

// Logout handles user logout
// POST /api/auth/logout
func (h *AuthHandler) Logout(c *fiber.Ctx) error {
	// Get session token from cookie
	sessionToken := c.Cookies("session_token")
	if sessionToken != "" {
		// Invalidate session in database
		h.authService.InvalidateSession(c.Context(), sessionToken)
	}

	// Clear session cookie (no refresh token cookie for cookie-based auth)
	c.Cookie(&fiber.Cookie{
		Name:     "session_token",
		Value:    "",
		MaxAge:   -1,
		Path:     "/",
		Secure:   true,
		HTTPOnly: true,
	})

	return c.JSON(fiber.Map{
		"message": "Logout successful",
	})
} // RevokeAllSessions handles security incident - revoke all user sessions
// POST /api/auth/revoke-all
func (h *AuthHandler) RevokeAllSessions(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(string)
	if userID == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Authentication required",
		})
	}

	err := h.authService.InvalidateAllUserSessions(c.Context(), userID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   "Failed to revoke sessions",
			"details": err.Error(),
		})
	}

	return c.JSON(fiber.Map{
		"message": "All sessions revoked successfully",
		"action":  "Please login again on all devices",
		"user_id": userID,
	})
}

// GetActiveSessions returns all active sessions for current user
// GET /api/auth/sessions
func (h *AuthHandler) GetActiveSessions(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(string)
	if userID == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Authentication required",
		})
	}

	// Get current session token for identifying current session
	currentSessionToken := c.Cookies("session_token")
	if currentSessionToken == "" {
		// For JWT auth, we might not have current session token
		// We'll pass empty string and service will handle it
		currentSessionToken = ""
	}

	sessions, err := h.authService.GetActiveUserSessions(c.Context(), userID, currentSessionToken)
	if err != nil {
		log.Printf("Failed to get user sessions: %v", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   "Failed to retrieve sessions",
			"details": err.Error(),
		})
	}

	return c.JSON(fiber.Map{
		"message": "Active sessions retrieved successfully",
		"data":    sessions,
	})
}

// Health check endpoint
// GET /health
func (h *AuthHandler) Health(c *fiber.Ctx) error {
	return c.JSON(fiber.Map{
		"status":  "healthy",
		"service": "authentication-service",
		"version": "0.1.0",
		"security": fiber.Map{
			"session_management": "enabled",
			"auto_revoke":        "enabled",
			"ip_validation":      "strict",
			"device_tracking":    "enabled",
		},
	})
}
