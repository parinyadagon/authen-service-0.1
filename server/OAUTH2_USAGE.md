# OAuth2 Authorization Code Flow - Usage Guide

## 🔄 OAuth2 Authorization Code Flow Overview

The OAuth2 Authorization Code Flow is the most secure way for web applications to obtain access tokens. It involves redirecting users to the authorization server, getting an authorization code, and then exchanging that code for tokens.

## 📋 Prerequisites

1. **Start the Server**
   ```bash
   cd server
   air  # or go run cmd/main.go
   ```

2. **Setup Database** (if not done)
   ```bash
   # Run schema and sample data
   mysql -u root -p authen_db < ../schema.md
   mysql -u root -p authen_db < scripts/sample_data.sql
   ```

3. **Available Test Clients** (from sample data):
   - `web-client` - Web Application
   - `mobile-app` - Mobile Application
   - `api-client` - API Client

## 🚀 Step-by-Step Authorization Code Flow

### Step 1: User Registration/Login (Optional)
First, create a user account or use existing test users:

```bash
# Register new user
curl -X POST http://localhost:8080/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "newuser",
    "password": "password123",
    "email": "newuser@example.com",
    "first_name": "New",
    "last_name": "User"
  }'

# Or login with existing user
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "password": "password123"
  }'
```

**Test Users Available:**
- Username: `admin`, Password: `password123`
- Username: `testuser`, Password: `password123`
- Username: `guestuser`, Password: `password123`

### Step 2: Authorization Request
Direct the user's browser to the authorization endpoint:

```bash
# Authorization URL (normally opened in browser)
GET http://localhost:8080/oauth/authorize?response_type=code&client_id=web-client&redirect_uri=http://localhost:3000/callback&scope=read:profile write:profile&state=xyz123
```

**Query Parameters:**
- `response_type=code` - Required for authorization code flow
- `client_id` - Your client ID (e.g., "web-client")
- `redirect_uri` - Where to redirect after authorization
- `scope` - Requested permissions (space-separated)
- `state` - CSRF protection (recommended)

**For Testing with curl:**
```bash
curl -X GET "http://localhost:8080/oauth/authorize?response_type=code&client_id=web-client&redirect_uri=http://localhost:3000/callback&scope=read:profile write:profile&state=xyz123" \
  -H "X-User-ID: 550e8400-e29b-41d4-a716-446655440001"
```

**Response:**
```json
{
  "message": "Authorization successful",
  "data": {
    "code": "auth_code_12345",
    "state": "xyz123"
  }
}
```

### Step 3: Exchange Authorization Code for Tokens
Use the authorization code to get access and refresh tokens:

```bash
curl -X POST http://localhost:8080/oauth/token \
  -H "Content-Type: application/json" \
  -d '{
    "grant_type": "authorization_code",
    "code": "auth_code_12345",
    "client_id": "web-client",
    "client_secret": "your-client-secret-here",
    "redirect_uri": "http://localhost:3000/callback"
  }'
```

**Response:**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "refresh_token_67890",
  "scope": "read:profile write:profile"
}
```

### Step 4: Use Access Token
Use the access token to make authenticated requests:

```bash
curl -X GET http://localhost:8080/api/profile \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

### Step 5: Refresh Access Token (When Expired)
Use the refresh token to get a new access token:

```bash
curl -X POST http://localhost:8080/api/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{
    "refresh_token": "refresh_token_67890"
  }'
```

## 🔧 Complete Example Flow

Here's a complete example using curl commands:

```bash
# 1. Start with authorization request
curl -X GET "http://localhost:8080/oauth/authorize?response_type=code&client_id=web-client&redirect_uri=http://localhost:3000/callback&scope=read:profile write:profile&state=xyz123" \
  -H "X-User-ID: 550e8400-e29b-41d4-a716-446655440001"

# Response: {"message":"Authorization successful","data":{"code":"auth_1731234567890","state":"xyz123"}}

# 2. Exchange code for tokens
curl -X POST http://localhost:8080/oauth/token \
  -H "Content-Type: application/json" \
  -d '{
    "grant_type": "authorization_code",
    "code": "auth_1731234567890",
    "client_id": "web-client",
    "client_secret": "your-client-secret-here",
    "redirect_uri": "http://localhost:3000/callback"
  }'

# Response: Access token and refresh token

# 3. Use access token for API calls
curl -X GET http://localhost:8080/api/protected \
  -H "Authorization: Bearer <access_token>"

# 4. Refresh token when expired
curl -X POST http://localhost:8080/api/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{
    "refresh_token": "<refresh_token>"
  }'
```

## 🌐 Browser-Based Flow (Production)

In a real web application, the flow would work like this:

### 1. Frontend Redirect
```javascript
// JavaScript - redirect user to authorization server
const authUrl = new URL('http://localhost:8080/oauth/authorize');
authUrl.searchParams.set('response_type', 'code');
authUrl.searchParams.set('client_id', 'web-client');
authUrl.searchParams.set('redirect_uri', 'http://localhost:3000/callback');
authUrl.searchParams.set('scope', 'read:profile write:profile');
authUrl.searchParams.set('state', generateRandomState());

window.location.href = authUrl.toString();
```

### 2. Handle Callback
```javascript
// JavaScript - handle the callback with authorization code
const urlParams = new URLSearchParams(window.location.search);
const code = urlParams.get('code');
const state = urlParams.get('state');

if (code) {
  // Exchange code for tokens
  const response = await fetch('http://localhost:8080/oauth/token', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      grant_type: 'authorization_code',
      code: code,
      client_id: 'web-client',
      client_secret: 'your-client-secret-here',
      redirect_uri: 'http://localhost:3000/callback'
    })
  });
  
  const tokens = await response.json();
  // Store tokens securely
  localStorage.setItem('access_token', tokens.access_token);
  localStorage.setItem('refresh_token', tokens.refresh_token);
}
```

## 🔐 Security Best Practices

### 1. **State Parameter**
Always use the `state` parameter to prevent CSRF attacks:
```bash
# Generate random state
state=$(openssl rand -hex 16)
# Include in authorization URL
"&state=$state"
```

### 2. **PKCE (Proof Key for Code Exchange)**
For enhanced security, especially for mobile apps:
```bash
# Generate code verifier and challenge
code_verifier=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-43)
code_challenge=$(echo -n $code_verifier | openssl dgst -sha256 -binary | openssl base64 | tr -d "=+/" | cut -c1-43)

# Include in authorization request
"&code_challenge=$code_challenge&code_challenge_method=S256"

# Include verifier in token exchange
"code_verifier": "$code_verifier"
```

### 3. **Secure Token Storage**
- **Web Apps**: Use httpOnly cookies
- **SPAs**: Use secure storage (not localStorage for sensitive data)
- **Mobile Apps**: Use secure keychain/keystore

## 🧪 Testing Different Scenarios

### Test Different Clients
```bash
# Web client
client_id="web-client"
client_secret="your-client-secret-here"

# Mobile app  
client_id="mobile-app"
client_secret="your-mobile-secret-here"

# API client (client credentials flow)
client_id="api-client"
client_secret="your-api-secret-here"
```

### Test Different Scopes
```bash
# Basic profile access
scope="read:profile"

# Profile read/write
scope="read:profile write:profile"

# Admin access (for admin users)
scope="read:profile write:profile read:users write:users admin:all"
```

### Test Error Scenarios
```bash
# Invalid client
curl -X GET "http://localhost:8080/oauth/authorize?response_type=code&client_id=invalid-client&redirect_uri=http://localhost:3000/callback"

# Invalid code
curl -X POST http://localhost:8080/oauth/token \
  -H "Content-Type: application/json" \
  -d '{"grant_type": "authorization_code", "code": "invalid-code", "client_id": "web-client"}'

# Expired/invalid refresh token
curl -X POST http://localhost:8080/api/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"refresh_token": "invalid-token"}'
```

## 📚 Available Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/oauth/authorize` | GET | Start authorization flow |
| `/oauth/token` | POST | Exchange code for tokens |
| `/api/auth/register` | POST | User registration |
| `/api/auth/login` | POST | User login |
| `/api/auth/refresh` | POST | Refresh access token |
| `/health` | GET | Health check |

## 🔍 Troubleshooting

### Common Issues:

1. **"User authentication required"**
   - Add `X-User-ID` header for testing
   - In production, ensure user is logged in

2. **"Invalid client credentials"**
   - Check client_id and client_secret
   - Verify client exists in database

3. **"Authorization code not found"**
   - Code may be expired (check expiry time)
   - Code can only be used once

4. **"Invalid redirect URI"**
   - Must match exactly what's registered for the client
   - Check for trailing slashes, http vs https

This guide provides everything you need to implement and test the OAuth2 Authorization Code Flow with your authentication service! 🚀