package config

import "time"

// SessionConfig holds session management configuration
type SessionConfig struct {
	MaxConcurrentSessions int           `yaml:"max_concurrent_sessions" env:"MAX_CONCURRENT_SESSIONS" default:"3"`
	SessionTimeout        time.Duration `yaml:"session_timeout" env:"SESSION_TIMEOUT" default:"24h"`
	CleanupInterval       time.Duration `yaml:"cleanup_interval" env:"CLEANUP_INTERVAL" default:"1h"`
	AllowDeviceOverride   bool          `yaml:"allow_device_override" env:"ALLOW_DEVICE_OVERRIDE" default:"true"`
	RequireIPValidation   bool          `yaml:"require_ip_validation" env:"REQUIRE_IP_VALIDATION" default:"false"`
}

// SessionPolicy defines how to handle concurrent sessions
type SessionPolicy string

const (
	PolicyRejectNew   SessionPolicy = "reject_new"   // Reject new login if max reached
	PolicyEvictOldest SessionPolicy = "evict_oldest" // Remove oldest session
	PolicyEvictAll    SessionPolicy = "evict_all"    // Force logout all sessions
	PolicyAllowAll    SessionPolicy = "allow_all"    // No limit (not recommended)
)

// GetSessionPolicy returns current session policy
func (sc *SessionConfig) GetSessionPolicy() SessionPolicy {
	if sc.MaxConcurrentSessions <= 0 {
		return PolicyAllowAll
	}
	if sc.MaxConcurrentSessions == 1 {
		return PolicyEvictAll
	}
	return PolicyEvictOldest
}

// SecurityPolicy defines session security settings
type SecurityPolicy struct {
	StrictIPValidation        bool `yaml:"strict_ip_validation" env:"STRICT_IP_VALIDATION" default:"true"`
	StrictUserAgentValidation bool `yaml:"strict_useragent_validation" env:"STRICT_USERAGENT_VALIDATION" default:"true"`
	AutoRevokeOnViolation     bool `yaml:"auto_revoke_on_violation" env:"AUTO_REVOKE_ON_VIOLATION" default:"true"`
	RevokeAllOnCompromise     bool `yaml:"revoke_all_on_compromise" env:"REVOKE_ALL_ON_COMPROMISE" default:"false"`
}

// DefaultSessionConfig returns default session configuration
func DefaultSessionConfig() *SessionConfig {
	return &SessionConfig{
		MaxConcurrentSessions: 3,
		SessionTimeout:        24 * time.Hour,
		CleanupInterval:       1 * time.Hour,
		AllowDeviceOverride:   true,
		RequireIPValidation:   false,
	}
}

// DefaultSecurityPolicy returns default security policy
func DefaultSecurityPolicy() *SecurityPolicy {
	return &SecurityPolicy{
		StrictIPValidation:        true,  // Enable strict IP checking
		StrictUserAgentValidation: true,  // Enable strict User-Agent checking
		AutoRevokeOnViolation:     true,  // Auto-revoke compromised sessions
		RevokeAllOnCompromise:     false, // Don't revoke all user sessions (just the compromised one)
	}
}
