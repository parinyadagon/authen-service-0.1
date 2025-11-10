# Authentication Service - Repository Layer

## GoJet MySQL Implementation

### Database Setup

1. **Create Database:**
```sql
CREATE DATABASE authen_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
```

2. **Run Schema:**
```bash
mysql -u root -p authen_db < ../../schema.md
```

3. **Insert Sample Data:**
```bash
mysql -u root -p authen_db < scripts/sample_data.sql
```

### Environment Variables

```bash
export DB_HOST=localhost
export DB_USERNAME=root  
export DB_PASSWORD=your_password
export DB_NAME=authen_db
```

### Usage

```go
// Initialize database connection
config := &mysql.Config{
    Host:     "localhost",
    Port:     3306,
    Username: "root",
    Password: "password",
    Database: "authen_db",
}

db, err := mysql.NewConnection(config)
if err != nil {
    log.Fatal(err)
}
defer db.Close()

// Initialize repository
authRepo := mysql.NewAuthRepository(db)

// Initialize service
authService := service.NewAuthService(authRepo)
```

### Repository Methods Implemented

#### User Operations
- `FindUserByID(ctx, userID)` - Find user by UUID
- `FindUserByUserName(ctx, username)` - Find user by username  
- `FindUserByEmail(ctx, email)` - Find user by email
- `CreateUser(ctx, userWithRole)` - Create user with role (transaction)
- `IsEmailExists(ctx, email)` - Check email existence
- `IsUsernameExists(ctx, username)` - Check username existence

#### Role Operations
- `FindRoleByName(ctx, roleName)` - Find role by name
- `GetDefaultRole(ctx)` - Get default USER role

#### OAuth2 Client Operations
- `FindClientByID(ctx, clientID)` - Find OAuth2 client
- `ValidateClientCredentials(ctx, clientID, secret)` - Validate client

#### Authorization Code Operations
- `CreateAuthorizationCode(ctx, code)` - Store authorization code
- `FindAuthorizationCode(ctx, code)` - Find authorization code
- `DeleteAuthorizationCode(ctx, code)` - Delete used code

#### Token Operations
- `StoreAccessToken(ctx, token)` - Store access token for revocation
- `FindAccessToken(ctx, tokenID)` - Find access token
- `RevokeAccessToken(ctx, tokenID)` - Revoke access token
- `StoreRefreshToken(ctx, token)` - Store refresh token
- `FindRefreshToken(ctx, tokenID)` - Find refresh token
- `RevokeRefreshToken(ctx, tokenID)` - Revoke refresh token
- `RevokeAllUserTokens(ctx, userID)` - Revoke all user tokens

#### User Consent Operations
- `CreateUserConsent(ctx, consent)` - Store user consent
- `FindUserConsent(ctx, userID, clientID)` - Find user consent

### Security Features

- **SQL Injection Protection**: Using GoJet parameterized queries
- **Transaction Support**: User creation with role assignment
- **Connection Pooling**: Configurable connection pool settings
- **Password Hashing**: Ready for Argon2 integration
- **Token Revocation**: Support for revoking tokens
- **Audit Trail**: Timestamps on all operations

### Testing

```bash
# Run tests
go test ./internal/adapters/driven/mysql/...

# Run with coverage
go test -cover ./internal/adapters/driven/mysql/...
```

### Performance Considerations

- **Indexes**: Ensure proper indexes on frequently queried columns
- **Connection Pool**: Tuned for production workload
- **Query Optimization**: Using efficient JOIN patterns
- **Batch Operations**: Where applicable for bulk operations

### Next Steps

1. Add proper client secret hashing
2. Implement token cleanup jobs
3. Add database migrations
4. Add integration tests
5. Add monitoring/metrics
6. Implement caching layer