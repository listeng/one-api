-- 添加CAS ID字段到users表
ALTER TABLE users ADD COLUMN cas_id VARCHAR(255) DEFAULT NULL;
CREATE INDEX idx_users_cas_id ON users(cas_id);

-- 添加CAS相关配置到options表
INSERT INTO options (key, value) VALUES 
('CASAuthEnabled', 'false'),
('CASLoginURL', ''),
('CASValidateURL', ''),
('CASLogoutURL', ''),
('CASRealm', ''),
('CASAdminRole', ''),
('CASCreateNewUser', 'true')
ON CONFLICT(key) DO NOTHING; 