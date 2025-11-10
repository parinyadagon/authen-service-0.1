package handlers

import (
	"net/http"

	"server/internal/core/domain"
	"server/internal/core/ports"

	"github.com/gin-gonic/gin"
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
func (h *AuthHandler) Register(c *gin.Context) {
	var req domain.RegisterReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Invalid request format",
			"details": err.Error(),
		})
		return
	}

	resp, err := h.authService.Register(c.Request.Context(), &req)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Registration failed",
			"details": err.Error(),
		})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"message": "User registered successfully",
		"data":    resp,
	})
}

// Login handles user authentication (Hybrid: Cookie + JWT)
// POST /api/auth/login
func (h *AuthHandler) Login(c *gin.Context) {
	var req domain.AuthReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Invalid request format",
			"details": err.Error(),
		})
		return
	}

	// Auto-detect auth type if not specified
	if req.AuthType == "" {
		userAgent := c.GetHeader("User-Agent")
		acceptHeader := c.GetHeader("Accept")

		// If request from browser, use cookie
		if userAgent != "" && (acceptHeader == "" || acceptHeader == "text/html" || acceptHeader == "*/*") {
			req.AuthType = "cookie"
		} else {
			req.AuthType = "jwt"
		}
	}

	resp, err := h.authService.Login(c.Request.Context(), &req)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":   "Authentication failed",
			"details": err.Error(),
		})
		return
	}

	// Handle response based on auth type
	if resp.AuthType == "cookie" {
		h.setCookieAuth(c, resp)
	} else {
		h.setJWTAuth(c, resp)
	}
}

// Set cookie-based authentication
func (h *AuthHandler) setCookieAuth(c *gin.Context, resp *domain.AuthResp) {
	// Set secure httpOnly cookies
	c.SetSameSite(http.SameSiteStrictMode)

	// Session cookie (httpOnly for XSS protection)
	c.SetCookie(
		"session_token",   // name
		resp.SessionToken, // value
		24*60*60,          // maxAge (24 hours)
		"/",               // path
		"",                // domain
		true,              // secure (HTTPS only in production)
		true,              // httpOnly
	)

	// Also set refresh token as httpOnly cookie
	if resp.RefreshToken != "" {
		c.SetCookie(
			"refresh_token",
			resp.RefreshToken,
			7*24*60*60, // 7 days
			"/",
			"",
			true, // secure
			true, // httpOnly
		)
	}

	// Return user info only (no sensitive tokens in response body)
	c.JSON(http.StatusOK, gin.H{
		"message":   "Login successful",
		"auth_type": "cookie",
		"user":      resp.User,
	})
}

// Set JWT-based authentication
func (h *AuthHandler) setJWTAuth(c *gin.Context, resp *domain.AuthResp) {
	c.JSON(http.StatusOK, gin.H{
		"message":   "Login successful",
		"auth_type": "jwt",
		"data": gin.H{
			"access_token":  resp.AccessToken,
			"refresh_token": resp.RefreshToken,
			"user":          resp.User,
		},
	})
}

// Refresh handles token refresh
// POST /api/auth/refresh
func (h *AuthHandler) Refresh(c *gin.Context) {
	var req domain.RefreshReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Invalid request format",
			"details": err.Error(),
		})
		return
	}

	resp, err := h.authService.Refresh(c.Request.Context(), req.RefreshToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":   "Token refresh failed",
			"details": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Token refreshed successfully",
		"data":    resp,
	})
}

// Authorize handles OAuth2 authorization
// GET /oauth/authorize
func (h *AuthHandler) Authorize(c *gin.Context) {
	var req domain.AuthorizeReq
	if err := c.ShouldBindQuery(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Invalid request parameters",
			"details": err.Error(),
		})
		return
	}

	// In a real implementation, you would:
	// 1. Check if user is authenticated (session/cookie)
	// 2. Show consent page if needed
	// 3. Get user consent
	// For now, we'll use a mock user ID
	userID := c.GetHeader("X-User-ID")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":   "User authentication required",
			"details": "Please login first or provide X-User-ID header for testing",
		})
		return
	}

	resp, err := h.authService.Authorize(c.Request.Context(), &req, userID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Authorization failed",
			"details": err.Error(),
		})
		return
	}

	// In OAuth2, this would typically redirect to client with code
	// For API testing, we return JSON
	c.JSON(http.StatusOK, gin.H{
		"message": "Authorization successful",
		"data":    resp,
	})
}

// Token handles OAuth2 token exchange
// POST /oauth/token
func (h *AuthHandler) Token(c *gin.Context) {
	var req domain.TokenReq
	if err := c.ShouldBindJSON(&req); err != nil {
		// Try form binding as OAuth2 typically uses form data
		if err := c.ShouldBind(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "Invalid request format",
				"details": err.Error(),
			})
			return
		}
	}

	resp, err := h.authService.Token(c.Request.Context(), &req)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Token exchange failed",
			"details": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, resp)
}

// Health check endpoint
// GET /health
func (h *AuthHandler) Health(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":  "healthy",
		"service": "authentication-service",
		"version": "0.1.0",
	})
}
