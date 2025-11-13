-- Clear existing data (optional - be careful in production!)
SET FOREIGN_KEY_CHECKS = 0;
TRUNCATE TABLE user_consents;
TRUNCATE TABLE refresh_tokens;
TRUNCATE TABLE access_tokens;
TRUNCATE TABLE authorization_codes;
TRUNCATE TABLE user_roles;
TRUNCATE TABLE role_permissions;
TRUNCATE TABLE users;
TRUNCATE TABLE clients;
TRUNCATE TABLE permissions;
TRUNCATE TABLE roles;
SET FOREIGN_KEY_CHECKS = 1;

-- Insert sample roles
INSERT INTO roles (name) VALUES 
('USER'),
('ADMIN'),
('GUEST');

-- Insert sample permissions
INSERT INTO permissions (name) VALUES 
('read:profile'),
('write:profile'),
('read:users'),
('write:users'),
('admin:all');

-- Assign permissions to roles
INSERT INTO role_permissions (role_id, permission_id) VALUES 
-- USER role permissions
(1, 1), -- read:profile
(1, 2), -- write:profile

-- ADMIN role permissions  
(2, 1), -- read:profile
(2, 2), -- write:profile
(2, 3), -- read:users
(2, 4), -- write:users
(2, 5), -- admin:all

-- GUEST role permissions
(3, 1); -- read:profile only

-- Insert sample users
-- Password for all users: "password123" 
-- Hashed with Argon2: $argon2id$v=19$m=65536,t=3,p=4$salt$hash (this is example, will be generated properly)
INSERT INTO users (id, username, password_hash, email, first_name, last_name, is_active, is_verified, created_at) VALUES 
('550e8400-e29b-41d4-a716-446655440000', 'admin', '$argon2id$v=19$m=65536,t=3,p=4$dGVzdHNhbHQ$VwQD5kqLOm5oMOUpwKUqCkGhU2RQy+GJzB1H0eN1h9Y', 'admin@example.com', 'Admin', 'User', 1, 1, NOW()),
('550e8400-e29b-41d4-a716-446655440001', 'testuser', '$argon2id$v=19$m=65536,t=3,p=4$dGVzdHNhbHQ$VwQD5kqLOm5oMOUpwKUqCkGhU2RQy+GJzB1H0eN1h9Y', 'testuser@example.com', 'Test', 'User', 1, 1, NOW()),
('550e8400-e29b-41d4-a716-446655440002', 'guestuser', '$argon2id$v=19$m=65536,t=3,p=4$dGVzdHNhbHQ$VwQD5kqLOm5oMOUpwKUqCkGhU2RQy+GJzB1H0eN1h9Y', 'guest@example.com', 'Guest', 'User', 1, 0, NOW());

-- Assign roles to users
INSERT INTO user_roles (user_id, role_id) VALUES 
('550e8400-e29b-41d4-a716-446655440000', 2), -- admin user -> ADMIN role
('550e8400-e29b-41d4-a716-446655440001', 1), -- test user -> USER role
('550e8400-e29b-41d4-a716-446655440002', 3); -- guest user -> GUEST role

-- Insert sample OAuth2 clients
INSERT INTO clients (id, client_secret_hash, client_name, redirect_uris, allowed_grant_types, owner_user_id) VALUES 
('web-client', 'your-client-secret-here', 'Web Application', 'http://localhost:3000/callback,http://localhost:3000/auth/callback', 'authorization_code,refresh_token', '550e8400-e29b-41d4-a716-446655440000'),
('test-client-1', 'test-client-secret-1', 'Demo OAuth Client', 'http://localhost:3000/callback', 'authorization_code,refresh_token', '550e8400-e29b-41d4-a716-446655440001'),
('trusted-app', 'trusted-app-secret', 'Trusted Enterprise App', 'http://localhost:3000/callback,https://app.company.com/callback', 'authorization_code,refresh_token,client_credentials', '550e8400-e29b-41d4-a716-446655440000'),
('mobile-app', 'your-mobile-secret-here', 'Mobile Application', 'myapp://callback', 'authorization_code,refresh_token', '550e8400-e29b-41d4-a716-446655440000'),
('api-client', 'your-api-secret-here', 'API Client', 'http://localhost:3000/api/callback', 'client_credentials', '550e8400-e29b-41d4-a716-446655440000');

-- Sample user consents
INSERT INTO user_consents (user_id, client_id, scopes_granted) VALUES 
('550e8400-e29b-41d4-a716-446655440000', 'web-client', 'read:profile write:profile read:users write:users'),
('550e8400-e29b-41d4-a716-446655440000', 'trusted-app', 'read:profile write:profile read:users write:users admin:all'),
('550e8400-e29b-41d4-a716-446655440001', 'web-client', 'read:profile write:profile'),
('550e8400-e29b-41d4-a716-446655440001', 'test-client-1', 'read:profile'),
('550e8400-e29b-41d4-a716-446655440001', 'mobile-app', 'read:profile');

-- Display inserted data for verification
SELECT 'Users:' as table_name;
SELECT id, username, email, first_name, last_name, is_active, is_verified FROM users;

SELECT 'Roles:' as table_name;
SELECT r.name, GROUP_CONCAT(u.username) as users 
FROM roles r 
LEFT JOIN user_roles ur ON r.id = ur.role_id 
LEFT JOIN users u ON ur.user_id = u.id 
GROUP BY r.id, r.name;

SELECT 'Clients:' as table_name;
SELECT id, client_name, redirect_uris FROM clients;