package handlers

import (
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

	resp, err := h.authService.Login(c.Context(), &req)
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

	// Also set refresh token as httpOnly cookie
	if resp.RefreshToken != "" {
		c.Cookie(&fiber.Cookie{
			Name:     "refresh_token",
			Value:    resp.RefreshToken,
			MaxAge:   7 * 24 * 60 * 60, // 7 days
			Path:     "/",
			Secure:   true,
			HTTPOnly: true,
			SameSite: "Strict",
		})
	}

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
	if err := c.QueryParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   "Invalid request parameters",
			"details": err.Error(),
		})
	}

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
	// Clear cookies
	c.Cookie(&fiber.Cookie{
		Name:     "session_token",
		Value:    "",
		MaxAge:   -1,
		Path:     "/",
		Secure:   true,
		HTTPOnly: true,
	})

	c.Cookie(&fiber.Cookie{
		Name:     "refresh_token",
		Value:    "",
		MaxAge:   -1,
		Path:     "/",
		Secure:   true,
		HTTPOnly: true,
	})

	return c.JSON(fiber.Map{
		"message": "Logout successful",
	})
}

// Health check endpoint
// GET /health
func (h *AuthHandler) Health(c *fiber.Ctx) error {
	return c.JSON(fiber.Map{
		"status":  "healthy",
		"service": "authentication-service",
		"version": "0.1.0",
	})
}
