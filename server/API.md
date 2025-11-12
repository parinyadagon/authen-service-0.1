# 🔐 Authentication Service API

**Version:** 0.1.0  
**Base URL:** `http://localhost:8080`  
**Framework:** Go Fiber v2.52.9 (High Performance)

## 🚀 Features

- **🔄 Hybrid Authentication**: JWT tokens + httpOnly cookies
- **🛡️ Advanced Security**: IP validation, device tracking, auto-revoke
- **⚡ Session Management**: Multi-device support with concurrent limits (max 3 sessions)
- **🔐 OAuth2 Flow**: Complete Authorization Code Flow
- **📱 Multi-platform**: Web, mobile, API clients support
- **🔒 Enterprise Security**: Real-time compromise detection & auto-session extension
- **🎯 Smart Token Management**: Optimized refresh token creation based on auth type

## Quick Start

1. **Setup Environment:**
```bash
cp .env.example .env
# Edit .env with your database credentials
```

2. **Run Database Setup:**
```bash
# Create database
mysql -u root -p -e "CREATE DATABASE authen_db CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci;"

# Run schema
mysql -u root -p authen_db < ../../schema.md

# Insert sample data
mysql -u root -p authen_db < scripts/sample_data.sql
```

3. **Start Server:**
```bash
go run cmd/main.go
# or for development with auto-reload:
air
```

Server will start on `http://localhost:8080`

## 🔄 OAuth2 Authorization Code Flow

For detailed OAuth2 usage instructions, see **[OAUTH2_USAGE.md](./OAUTH2_USAGE.md)**

**Quick OAuth2 Flow:**
1. **Authorize**: `GET /oauth/authorize` → Get authorization code
2. **Token Exchange**: `POST /oauth/token` → Exchange code for tokens  
3. **Use Token**: Include `Authorization: Bearer <token>` in requests
4. **Refresh**: `POST /api/auth/refresh` → Get new tokens when expired

## 🔐 Authentication Types

### 1. JWT Token Authentication
- **Use Case**: Mobile apps, API clients
- **Headers**: `Authorization: Bearer <token>`
- **Features**: Stateless, portable, includes refresh tokens

### 2. Cookie-Based Authentication  
- **Use Case**: Web browsers, same-origin requests
- **Headers**: Automatic cookie handling
- **Features**: httpOnly cookies, CSRF protection, no refresh tokens needed

### 3. Hybrid Detection
The system automatically detects client type and provides appropriate authentication method:
- **API Clients**: Receives JWT tokens in response body
- **Web Browsers**: Receives httpOnly cookies + simplified JSON response

## 📡 API Endpoints

### 🟢 Public Endpoints

#### Health Check
```
GET /health
```

**Response:**
```json
{
  "status": "healthy",
  "service": "authentication-service",
  "version": "0.1.0"
}
```

#### User Registration
```
POST /api/auth/register
```

**Request:**
```json
{
  "user_name": "testuser",
  "first_name": "Test",
  "last_name": "User",
  "email": "test@example.com",
  "password": "password123"
}
```

**Response:**
```json
{
  "message": "User registered successfully",
  "data": {
    "user_name": "testuser",
    "first_name": "Test",
    "last_name": "User",
    "email": "test@example.com"
  }
}
```

#### User Login
```http
POST /api/auth/login
Content-Type: application/json
```

**Request:**
```json
{
  "user_name": "testuser", 
  "password": "password123",
  "remember_me": false
}
```

**JWT Response (API Clients):**
```json
{
  "message": "Login successful",
  "data": {
    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "user": {
      "user_id": "550e8400-e29b-41d4-a716-446655440001",
      "user_name": "testuser",
      "first_name": "Test", 
      "last_name": "User",
      "email": "test@example.com",
      "is_active": true
    }
  }
}
```

**Cookie Response (Web Browsers):**
```json
{
  "message": "Login successful",
  "data": {
    "user": {
      "user_id": "550e8400-e29b-41d4-a716-446655440001",
      "user_name": "testuser",
      "first_name": "Test",
      "last_name": "User", 
      "email": "test@example.com",
      "is_active": true
    }
  }
}
```
*Note: httpOnly cookies are automatically set for web browsers*

#### Token Refresh (JWT Only)
```http
POST /api/auth/refresh
Content-Type: application/json
```

**Request:**
```json
{
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

**Response:**
```json
{
  "message": "Token refreshed successfully",
  "data": {
    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
  }
}
```
*Note: Cookie-based auth doesn't need refresh - sessions auto-extend when active*

### 🔒 Protected Endpoints (Require Authentication)

#### User Profile
```http
GET /api/profile
Authorization: Bearer <access_token>
# OR automatic cookie authentication
```

**Response:**
```json
{
  "user_id": "550e8400-e29b-41d4-a716-446655440001",
  "username": "testuser", 
  "message": "This is a protected endpoint"
}
```

---

#### Get Active Sessions
```http
GET /api/sessions
Authorization: Bearer <access_token>
# OR automatic cookie authentication
```

**Purpose**: View all active sessions for the current user

**Response:**
```json
{
  "message": "Active sessions retrieved successfully",  
  "data": {
    "sessions": [
      {
        "session_id": "sess_123...",
        "created_at": "2024-01-15T10:30:00Z",
        "last_activity": "2024-01-15T12:45:00Z", 
        "ip_address": "192.168.1.100",
        "user_agent": "Mozilla/5.0...",
        "device_info": "Chrome on Windows",
        "is_current": true
      },
      {
        "session_id": "sess_456...",
        "created_at": "2024-01-14T15:20:00Z", 
        "last_activity": "2024-01-15T09:15:00Z",
        "ip_address": "10.0.0.50", 
        "user_agent": "MyApp/1.0...",
        "device_info": "Mobile App on iOS",
        "is_current": false
      }
    ],
    "total_sessions": 2,
    "max_sessions": 3
  }
}
```

---

#### Revoke All Sessions  
```http
POST /api/revoke-all
Authorization: Bearer <access_token>
# OR automatic cookie authentication
```

**Purpose**: Immediately revoke all sessions for the current user (security feature)

**Request (Optional):**
```json
{
  "keep_current": false
}
```

**Response:**
```json
{
  "message": "All sessions revoked successfully",
  "data": {
    "revoked_sessions": 3,
    "current_session_kept": false
  }
}
```

*Use Cases:*
- 🚨 **Security Breach**: User suspects account compromise
- 📱 **Device Loss**: User lost device with active session  
- 🔄 **Fresh Start**: Clean slate for all devices
- 👤 **Account Takeover**: Admin security response

---

### 🔐 OAuth2 Endpoints

#### Authorization
```
GET /oauth/authorize?client_id=web-client&redirect_uri=http://localhost:3000/callback&scope=read:profile&state=xyz&response_type=code
X-User-ID: 550e8400-e29b-41d4-a716-446655440001
```

**Response:**
```json
{
  "message": "Authorization successful",
  "data": {
    "code": "auth_code_here",
    "state": "xyz",
    "redirect_uri": "http://localhost:3000/callback"
  }
}
```

#### Token Exchange
```
POST /oauth/token
```

**Request:**
```json
{
  "grant_type": "authorization_code",
  "code": "auth_code_here",
  "client_id": "web-client",
  "client_secret": "your-client-secret-here",
  "redirect_uri": "http://localhost:3000/callback"
}
```

**Response:**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 900,
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "scope": "read:profile"
}
```

---

## 🛡️ Security Features

### Session Management
- **Concurrent Limit**: Maximum 3 active sessions per user
- **Auto-Eviction**: Oldest sessions removed when limit exceeded
- **Activity Tracking**: Sessions extend automatically when active (15min intervals)
- **IP Validation**: Sessions tied to originating IP address
- **Device Fingerprinting**: Unique device identification for security

### Real-time Security Monitoring
- **IP Change Detection**: Auto-revoke if session used from different IP
- **Device Change Detection**: Auto-revoke if device fingerprint changes  
- **Compromise Detection**: Automatic session invalidation on security violations
- **Audit Logging**: All security events logged with timestamps and context  

### Session Lifecycle
```
Login → Session Created → Activity Monitored → Auto-Extend (if active) → Natural Expiry/Revoke
   ↓                           ↓                       ↓
Security Check            Security Check          Security Check
   ↓                           ↓                       ↓  
Auto-Revoke (if needed)   Auto-Revoke (if needed)  Auto-Revoke (if needed)
```

### Auto-Extension Logic
Sessions automatically extend when:
- ✅ User makes authenticated request  
- ✅ IP address matches session origin
- ✅ Device fingerprint matches
- ✅ Last extension was >15 minutes ago  
- ✅ Session is not flagged as compromised

## 🧪 Testing with cURL

### Register User
```bash
curl -X POST http://localhost:8080/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "user_name": "newuser",
    "first_name": "New",
    "last_name": "User", 
    "email": "newuser@example.com",
    "password": "password123"
  }'
```

### Login (JWT)  
```bash
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -H "User-Agent: MyApp/1.0" \
  -d '{
    "user_name": "testuser",
    "password": "password123"
  }'
```

### Login (Cookie)
```bash  
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -H "User-Agent: Mozilla/5.0" \
  -c cookies.txt \
  -d '{
    "user_name": "testuser", 
    "password": "password123"
  }'
```

### Access Protected Endpoint (JWT)
```bash
curl -X GET http://localhost:8080/api/profile \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN_HERE"
```

### Access Protected Endpoint (Cookie)
```bash
curl -X GET http://localhost:8080/api/profile \
  -b cookies.txt
```

### View Active Sessions
```bash
curl -X GET http://localhost:8080/api/sessions \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN_HERE"
```

### Revoke All Sessions
```bash  
curl -X POST http://localhost:8080/api/revoke-all \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN_HERE" \
  -H "Content-Type: application/json" \
  -d '{"keep_current": false}'
```

### OAuth2 Authorization
```bash
curl -X GET "http://localhost:8080/oauth/authorize?client_id=web-client&redirect_uri=http://localhost:3000/callback&scope=read:profile&state=xyz&response_type=code" \
  -H "X-User-ID: 550e8400-e29b-41d4-a716-446655440001"
```

## ⚠️ Error Responses

All errors follow this format:
```json
{
  "error": "Brief error description",
  "details": "Detailed error message"
}
```

### Common HTTP Status Codes:
- `400` - Bad Request (invalid input, validation failed)
- `401` - Unauthorized (authentication failed, invalid token)  
- `403` - Forbidden (insufficient permissions, session limit exceeded)
- `404` - Not Found (endpoint or resource not found)
- `409` - Conflict (user already exists, session conflicts)
- `429` - Too Many Requests (rate limiting, security throttling)
- `500` - Internal Server Error (server-side issues)

### Security-Specific Errors:
```json
{
  "error": "Session limit exceeded", 
  "details": "Maximum 3 concurrent sessions allowed. Oldest session will be revoked."
}
```

```json
{
  "error": "Session compromised",
  "details": "IP address or device mismatch detected. Session revoked for security."
}
```

```json
{
  "error": "Authentication method not supported",
  "details": "This endpoint requires JWT authentication, cookie auth not supported."
}
```

## 📊 Sample Test Data

Use these credentials for testing:

### Users
**Admin User:**
- Username: `admin`
- Password: `password123`
- Email: `admin@example.com`

**Regular User:**
- Username: `testuser`
- Password: `password123`
- Email: `testuser@example.com`

### OAuth2 Clients
**Web Client:**
- Client ID: `web-client`
- Client Secret: `your-client-secret-here`
- Redirect URI: `http://localhost:3000/callback`

## 🎯 Integration Examples

### Web Application (Cookie Auth)
```javascript
// Login
const response = await fetch('/api/auth/login', {
  method: 'POST',
  credentials: 'include', // Include cookies
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    user_name: 'testuser',
    password: 'password123'
  })
});

// Subsequent requests automatically include cookies
const profile = await fetch('/api/profile', {
  credentials: 'include'  
});
```

### Mobile App (JWT Auth)  
```javascript
// Login
const loginResponse = await fetch('/api/auth/login', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'User-Agent': 'MyMobileApp/1.0'
  },
  body: JSON.stringify({
    user_name: 'testuser',
    password: 'password123'
  })
});

const tokens = await loginResponse.json();
localStorage.setItem('access_token', tokens.data.access_token);
localStorage.setItem('refresh_token', tokens.data.refresh_token);

// Use token for requests
const profile = await fetch('/api/profile', {
  headers: {
    'Authorization': `Bearer ${localStorage.getItem('access_token')}`
  }
});
```

### Session Management UI
```javascript
// Get active sessions
const sessions = await fetch('/api/sessions', {
  credentials: 'include'
}).then(r => r.json());

console.log(`Active sessions: ${sessions.data.total_sessions}/${sessions.data.max_sessions}`);

// Emergency: Revoke all sessions
const revokeAll = await fetch('/api/revoke-all', {
  method: 'POST',
  credentials: 'include',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ keep_current: false })
});
```

## 🔧 Advanced Configuration

### Session Configuration (config/session.go)
```go
SessionConfig{
    MaxConcurrentSessions: 3,           // Max sessions per user
    SessionTimeout: 24 * time.Hour,     // Session lifetime  
    ExtensionInterval: 15 * time.Minute, // Auto-extend frequency
    SecurityCheckInterval: 5 * time.Minute, // Security scan frequency
    CleanupInterval: time.Hour,         // Cleanup old sessions
}
```

### Security Policies
- **IP Validation**: Strict IP checking (can be configured to allow IP ranges)
- **Device Fingerprinting**: User-Agent + custom headers for device identification  
- **Session Limits**: Configurable per-user concurrent session limits
- **Auto-Revoke**: Immediate session termination on security violations
- **Audit Trail**: Complete session lifecycle logging for security analysis

## 🚀 Performance & Scalability

### Go Fiber Advantages
- **High Performance**: Up to 10x faster than traditional frameworks
- **Low Memory**: Efficient memory usage with minimal overhead
- **Fast Routing**: Express.js-inspired routing with zero allocation
- **Built-in Middleware**: Compression, CORS, Rate Limiting, Logging

### Database Optimizations
- **Connection Pooling**: Optimized MySQL connection management
- **Indexed Queries**: All session lookups use proper database indexes
- **Batch Operations**: Efficient session cleanup with batch processing
- **Query Optimization**: Prepared statements for security and performance

## 🔍 Monitoring & Observability

### Health Checks
```bash
curl http://localhost:8080/health
```

### Metrics (Future Enhancement)
- Session creation/revocation rates
- Authentication success/failure rates  
- Security incident detection counts
- Response time distributions
- Active session counts per user

### Logging
- **Structured Logs**: JSON format for easy parsing
- **Security Events**: All authentication and session events logged
- **Performance Metrics**: Request duration and database query times
- **Error Tracking**: Detailed error context and stack traces

---

*Last Updated: November 2025 | Framework: Go Fiber v2.52.9 | Security: Enterprise Grade*