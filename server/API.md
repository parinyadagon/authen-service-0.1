# Authentication Service API

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

## API Endpoints

### Public Endpoints

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
```
POST /api/auth/login
```

**Request:**
```json
{
  "user_name": "testuser",
  "password": "password123",
  "remember_me": false
}
```

**Response:**
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

#### Token Refresh
```
POST /api/auth/refresh
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

### Protected Endpoints (Require JWT)

#### User Profile
```
GET /api/profile
Authorization: Bearer <access_token>
```

**Response:**
```json
{
  "user_id": "550e8400-e29b-41d4-a716-446655440001",
  "username": "testuser",
  "message": "This is a protected endpoint"
}
```

### OAuth2 Endpoints

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

## Testing with cURL

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

### Login
```bash
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "user_name": "testuser",
    "password": "password123"
  }'
```

### Access Protected Endpoint
```bash
curl -X GET http://localhost:8080/api/profile \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN_HERE"
```

### OAuth2 Authorization
```bash
curl -X GET "http://localhost:8080/oauth/authorize?client_id=web-client&redirect_uri=http://localhost:3000/callback&scope=read:profile&state=xyz&response_type=code" \
  -H "X-User-ID: 550e8400-e29b-41d4-a716-446655440001"
```

## Error Responses

All errors follow this format:
```json
{
  "error": "Brief error description",
  "details": "Detailed error message"
}
```

Common HTTP status codes:
- `400` - Bad Request (invalid input)
- `401` - Unauthorized (authentication failed)
- `403` - Forbidden (insufficient permissions)
- `404` - Not Found
- `500` - Internal Server Error

## Sample Test Data

Use these credentials for testing:

**Admin User:**
- Username: `admin`
- Password: `password123`
- Email: `admin@example.com`

**Regular User:**
- Username: `testuser`
- Password: `password123`
- Email: `testuser@example.com`

**OAuth2 Clients:**
- Client ID: `web-client`
- Client Secret: `your-client-secret-here`
- Redirect URI: `http://localhost:3000/callback`