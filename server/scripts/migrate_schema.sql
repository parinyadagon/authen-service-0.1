-- Migration script to update schema from old to new format
-- Run this script if you have an existing database with the old schema

-- 1. Update roles table column name
ALTER TABLE roles CHANGE COLUMN role_name name VARCHAR(50) NOT NULL;

-- 2. Update permissions table column name  
ALTER TABLE permissions CHANGE COLUMN permission_name name VARCHAR(100) NOT NULL;

-- 3. Update authorization_codes table column name
ALTER TABLE authorization_codes CHANGE COLUMN id code VARCHAR(128) NOT NULL;

-- 4. Update access_tokens table column name
ALTER TABLE access_tokens CHANGE COLUMN id token_hash VARCHAR(128) NOT NULL;

-- 5. Update refresh_tokens table column name
ALTER TABLE refresh_tokens CHANGE COLUMN id token_hash VARCHAR(128) NOT NULL;

-- 6. Update collation for all tables to utf8mb4_general_ci
ALTER TABLE users CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci;
ALTER TABLE roles CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci;
ALTER TABLE permissions CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci;
ALTER TABLE user_roles CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci;
ALTER TABLE role_permissions CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci;
ALTER TABLE clients CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci;
ALTER TABLE authorization_codes CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci;
ALTER TABLE access_tokens CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci;
ALTER TABLE refresh_tokens CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci;
ALTER TABLE user_consents CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci;

-- 7. Add user_sessions table for cookie-based authentication with security enhancements
CREATE TABLE IF NOT EXISTS user_sessions (
    session_token VARCHAR(128) NOT NULL PRIMARY KEY,
    user_id CHAR(36) NOT NULL,
    client_id VARCHAR(100) NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    is_active TINYINT(1) NOT NULL DEFAULT 1,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    ip_address VARCHAR(45) DEFAULT NULL,
    user_agent TEXT DEFAULT NULL,
    device_id VARCHAR(128) DEFAULT NULL,
    last_accessed TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_sessions_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE ON UPDATE CASCADE,
    INDEX idx_user_sessions_user_id (user_id),
    INDEX idx_user_sessions_expires (expires_at),
    INDEX idx_user_sessions_active (is_active)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- 8. Add columns to existing user_sessions table if it already exists (for migration)
ALTER TABLE user_sessions 
ADD COLUMN IF NOT EXISTS ip_address VARCHAR(45) DEFAULT NULL,
ADD COLUMN IF NOT EXISTS user_agent TEXT DEFAULT NULL,
ADD COLUMN IF NOT EXISTS device_id VARCHAR(128) DEFAULT NULL,
ADD COLUMN IF NOT EXISTS last_accessed TIMESTAMP DEFAULT CURRENT_TIMESTAMP;

-- 9. Add indexes for better performance
CREATE INDEX IF NOT EXISTS idx_user_sessions_user_id ON user_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_user_sessions_expires ON user_sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_user_sessions_active ON user_sessions(is_active);

-- Verify the changes
DESCRIBE roles;
DESCRIBE permissions;
DESCRIBE authorization_codes;  
DESCRIBE access_tokens;
DESCRIBE refresh_tokens;
DESCRIBE user_sessions;

SELECT 'Migration completed successfully!' as status;