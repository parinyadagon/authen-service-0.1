# Authentication Service - Setup Guide

## ✅ Implementation Complete

### What's Been Implemented:

1. **Environment Configuration (.env)**
   - Database connection settings
   - JWT configuration
   - Server configuration  
   - OAuth2 settings

2. **HTTP REST API**
   - User registration/login
   - Token refresh
   - OAuth2 authorization & token endpoints
   - Protected routes with JWT middleware
   - CORS, security headers, logging

3. **Sample Test Data**
   - 3 sample users (admin, testuser, guestuser)
   - 3 roles (USER, ADMIN, GUEST) with permissions
   - 3 OAuth2 clients for testing
   - User consents

## 🚀 Quick Start

### 1. Database Setup
```bash
# Create database
mysql -u root -p -e "CREATE DATABASE authen_db CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci;"

# Run schema
mysql -u root -p authen_db < ../../schema.md

# Insert sample data  
mysql -u root -p authen_db < scripts/sample_data.sql
```

### 2. Environment Configuration
```bash
# Copy and edit environment file
cp .env .env.local
# Edit .env with your actual database credentials
```

### 3. Start Server
```bash
# From server directory
go run cmd/main.go
```

Server will start on `http://localhost:8080`

## 🧪 Test the API

### Health Check
```bash
curl http://localhost:8080/health
```

### Register New User
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

### Login with Test User
```bash
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "user_name": "testuser",
    "password": "password123"
  }'
```

### Test Protected Endpoint
```bash
# Use access_token from login response
curl -X GET http://localhost:8080/api/profile \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN_HERE"
```

## 📚 Available Endpoints

- `GET /` - API documentation
- `GET /health` - Health check
- `POST /api/auth/register` - User registration
- `POST /api/auth/login` - User login
- `POST /api/auth/refresh` - Token refresh
- `GET /api/profile` - Protected user profile (requires JWT)
- `GET /oauth/authorize` - OAuth2 authorization
- `POST /oauth/token` - OAuth2 token exchange

## 🔑 Test Credentials

**Sample Users:**
- Username: `admin`, Password: `password123`
- Username: `testuser`, Password: `password123`
- Username: `guestuser`, Password: `password123`

**OAuth2 Client:**
- Client ID: `web-client`
- Client Secret: `your-client-secret-here`

## 📋 Project Structure

```
server/
├── cmd/main.go                          # Application entry point
├── internal/
│   ├── config/config.go                 # Environment configuration
│   ├── core/
│   │   ├── domain/                      # Domain entities
│   │   ├── ports/                       # Interface definitions
│   │   └── service/                     # Business logic
│   ├── adapters/
│   │   ├── driven/mysql/                # Database implementation
│   │   └── driving/http/                # HTTP handlers & routes
│   └── utils/                           # Utilities (JWT, password)
├── scripts/sample_data.sql              # Test data
├── .env                                 # Environment variables
├── API.md                               # API documentation
└── go.mod                               # Go dependencies
```

## 🔄 Next Steps

1. **Database Migration System** - Add proper migrations
2. **Email Verification** - Implement email verification flow
3. **Password Reset** - Add forgot password functionality
4. **Admin Panel** - Create admin endpoints
5. **Docker Support** - Add Dockerfile and docker-compose
6. **Testing** - Add comprehensive test suite
7. **Monitoring** - Add metrics and health checks
8. **Rate Limiting** - Implement proper rate limiting

## 🐛 Troubleshooting

**Database Connection Issues:**
- Check MySQL is running
- Verify credentials in `.env`
- Ensure database exists

**JWT Token Issues:**
- Check `JWT_SECRET_KEY` in `.env`
- Ensure key is at least 32 characters

**Permission Issues:**
- Verify user exists in `sample_data.sql`
- Check role assignments

The authentication service is now **fully functional** with JWT authentication, OAuth2 support, and a complete REST API! 🎉