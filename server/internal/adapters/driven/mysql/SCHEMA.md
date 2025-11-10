# Database Schema Documentation

## Schema Version: 2.0
**Updated**: November 10, 2025

## Overview
This document describes the updated MySQL database schema for the OAuth2 Authentication Service. The schema has been optimized and standardized with the following key changes:

### Key Changes from v1.0:
1. **Column Name Standardization**:
   - `roles.role_name` → `roles.name`
   - `permissions.permission_name` → `permissions.name`
   - `authorization_codes.id` → `authorization_codes.code`
   - `access_tokens.id` → `access_tokens.token_hash`
   - `refresh_tokens.id` → `refresh_tokens.token_hash`

2. **Collation Standardization**:
   - Changed from `utf8mb4_unicode_ci` to `utf8mb4_general_ci` for better performance

## Database Tables

### 1. users
Core user information table.
```sql
CREATE TABLE users (
    id CHAR(36) NOT NULL PRIMARY KEY,           -- UUID format
    username VARCHAR(50) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,        -- Argon2 hash
    email VARCHAR(100) NOT NULL UNIQUE,
    first_name VARCHAR(50),
    last_name VARCHAR(50),
    is_active TINYINT(1) NOT NULL DEFAULT 1,
    is_verified TINYINT(1) NOT NULL DEFAULT 0,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
```

### 2. roles
System roles definition.
```sql
CREATE TABLE roles (
    id INT NOT NULL PRIMARY KEY AUTO_INCREMENT,
    name VARCHAR(50) NOT NULL UNIQUE             -- e.g., 'USER', 'ADMIN', 'GUEST'
);
```

### 3. permissions
System permissions definition.
```sql
CREATE TABLE permissions (
    id INT NOT NULL PRIMARY KEY AUTO_INCREMENT,
    name VARCHAR(100) NOT NULL UNIQUE           -- e.g., 'read:profile', 'write:users'
);
```

### 4. user_roles
Many-to-many relationship between users and roles.
```sql
CREATE TABLE user_roles (
    user_id CHAR(36) NOT NULL,
    role_id INT NOT NULL,
    PRIMARY KEY (user_id, role_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE
);
```

### 5. role_permissions
Many-to-many relationship between roles and permissions.
```sql
CREATE TABLE role_permissions (
    role_id INT NOT NULL,
    permission_id INT NOT NULL,
    PRIMARY KEY (role_id, permission_id),
    FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
    FOREIGN KEY (permission_id) REFERENCES permissions(id) ON DELETE CASCADE
);
```

### 6. clients
OAuth2 client applications.
```sql
CREATE TABLE clients (
    id VARCHAR(100) NOT NULL PRIMARY KEY,       -- Public client identifier
    client_secret_hash VARCHAR(255) NOT NULL,   -- Hashed client secret
    client_name VARCHAR(100) NOT NULL,
    redirect_uris TEXT NOT NULL,                -- JSON array or comma-separated
    allowed_grant_types TEXT NOT NULL,          -- JSON array or comma-separated
    owner_user_id CHAR(36) NOT NULL,
    FOREIGN KEY (owner_user_id) REFERENCES users(id) ON DELETE RESTRICT
);
```

### 7. authorization_codes
OAuth2 authorization codes (PKCE support).
```sql
CREATE TABLE authorization_codes (
    code VARCHAR(128) NOT NULL PRIMARY KEY,     -- The authorization code itself
    user_id CHAR(36) NOT NULL,
    client_id VARCHAR(100) NOT NULL,
    scopes VARCHAR(255) NOT NULL,
    redirect_uri VARCHAR(255) NOT NULL,
    code_challenge VARCHAR(128),                -- PKCE code challenge
    code_challenge_method VARCHAR(10),          -- 'S256' or 'plain'
    expires_at TIMESTAMP NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE
);
```

### 8. access_tokens
OAuth2 access tokens.
```sql
CREATE TABLE access_tokens (
    token_hash VARCHAR(128) NOT NULL PRIMARY KEY, -- Hashed token or opaque identifier
    user_id CHAR(36) NOT NULL,
    client_id VARCHAR(100) NOT NULL,
    scopes VARCHAR(255) NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE
);
```

### 9. refresh_tokens
OAuth2 refresh tokens.
```sql
CREATE TABLE refresh_tokens (
    token_hash VARCHAR(128) NOT NULL PRIMARY KEY, -- Hashed refresh token
    user_id CHAR(36) NOT NULL,
    client_id VARCHAR(100) NOT NULL,
    scopes VARCHAR(255) NOT NULL,
    is_revoked TINYINT(1) NOT NULL DEFAULT 0,
    expires_at TIMESTAMP NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE
);
```

### 10. user_consents
User consent for OAuth2 applications.
```sql
CREATE TABLE user_consents (
    user_id CHAR(36) NOT NULL,
    client_id VARCHAR(100) NOT NULL,
    scopes_granted TEXT NOT NULL,               -- Space-separated scopes
    PRIMARY KEY (user_id, client_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE
);
```

## Migration Guide

### For New Installations:
1. Use the schema from `../schema.md`
2. Run the sample data from `scripts/sample_data.sql`

### For Existing Installations:
1. **Backup your database first!**
2. Run the migration script: `scripts/migrate_schema.sql`
3. Update your application code to use the new column names
4. Test thoroughly

### Migration Script Usage:
```bash
# Backup existing database
mysqldump -u root -p authen_db > backup_before_migration.sql

# Run migration
mysql -u root -p authen_db < scripts/migrate_schema.sql

# Verify migration
mysql -u root -p authen_db -e "DESCRIBE roles; DESCRIBE permissions;"
```

## Indexing Strategy

### Recommended Additional Indexes:
```sql
-- Performance indexes for common queries
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_active ON users(is_active);

CREATE INDEX idx_access_tokens_expires ON access_tokens(expires_at);
CREATE INDEX idx_refresh_tokens_expires ON refresh_tokens(expires_at);
CREATE INDEX idx_refresh_tokens_user ON refresh_tokens(user_id);

CREATE INDEX idx_authorization_codes_expires ON authorization_codes(expires_at);
CREATE INDEX idx_user_roles_user ON user_roles(user_id);
CREATE INDEX idx_user_roles_role ON user_roles(role_id);
```

## Sample Data

The system includes sample data with:
- **Users**: admin, testuser, guestuser (password: "password123")
- **Roles**: USER, ADMIN, GUEST
- **Permissions**: read:profile, write:profile, read:users, write:users, admin:all
- **OAuth2 Clients**: web-client, mobile-app, api-client

## Security Considerations

1. **Password Hashing**: Uses Argon2 algorithm
2. **Client Secrets**: Stored as hashes, not plain text
3. **Tokens**: Access tokens are JWTs, refresh tokens are opaque and hashed
4. **PKCE**: Supported for authorization code flow
5. **Foreign Keys**: Cascade deletes maintain referential integrity

## Performance Notes

1. **Collation**: Using `utf8mb4_general_ci` for better performance than `utf8mb4_unicode_ci`
2. **Primary Keys**: Optimized for common query patterns
3. **Token Storage**: Hashed tokens reduce collision risk and improve security
4. **Indexes**: Strategic indexing on frequently queried columns

## Troubleshooting

### Common Issues:
1. **Character Set Problems**: Ensure all tables use `utf8mb4` with `utf8mb4_general_ci`
2. **Foreign Key Constraints**: Check referential integrity during migration
3. **Column Name Mismatches**: Update application code to use new column names
4. **Token Collisions**: Hash-based primary keys reduce but don't eliminate collisions

### Verification Queries:
```sql
-- Check schema consistency
SELECT TABLE_NAME, TABLE_COLLATION FROM information_schema.TABLES 
WHERE TABLE_SCHEMA = 'authen_db';

-- Verify sample data
SELECT COUNT(*) as total_users FROM users;
SELECT COUNT(*) as total_roles FROM roles;
SELECT COUNT(*) as total_permissions FROM permissions;
```

---
**Note**: This schema is production-ready and follows OAuth2 security best practices. Always backup before migration!