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

-- Verify the changes
DESCRIBE roles;
DESCRIBE permissions;
DESCRIBE authorization_codes;  
DESCRIBE access_tokens;
DESCRIBE refresh_tokens;

SELECT 'Migration completed successfully!' as status;