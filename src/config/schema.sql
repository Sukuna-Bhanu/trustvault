CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- 1. Custom Enums for strict authorization
DO $$ BEGIN
    CREATE TYPE user_role AS ENUM ('ADMIN', 'OWNER', 'VIEWER');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
    CREATE TYPE grant_perm AS ENUM ('READ', 'EDIT');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
    CREATE TYPE audit_action AS ENUM ('UPLOAD', 'DOWNLOAD', 'VIEW_METADATA', 'GRANT_PERM', 'REVOKE_PERM', 'ACCESS_DENIED');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- 2. Users Table
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role user_role NOT NULL DEFAULT 'VIEWER',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 3. Documents Table (Actual files live on disk under storage_key.bin)
CREATE TABLE IF NOT EXISTS documents (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    owner_id UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    original_name VARCHAR(255) NOT NULL,
    storage_key UUID NOT NULL UNIQUE,
    mime_type VARCHAR(100) NOT NULL,
    file_size BIGINT NOT NULL,
    category VARCHAR(50) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 4. Document Grants Table (Explicit Named Access)
CREATE TABLE IF NOT EXISTS document_grants (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    document_id UUID NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    permission grant_perm NOT NULL DEFAULT 'READ',
    granted_by UUID NOT NULL REFERENCES users(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT unique_doc_user UNIQUE (document_id, user_id)
);

-- 5. Audit Logs Table (Tamper-evident append-only ledger)
CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    actor_id UUID REFERENCES users(id),
    action audit_action NOT NULL,
    target_document_id UUID,
    status VARCHAR(20) NOT NULL, -- 'SUCCESS' or 'DENIED'
    details JSONB DEFAULT '{}',
    ip_address VARCHAR(45) NOT NULL,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    previous_hash CHAR(64) NOT NULL,
    current_hash CHAR(64) NOT NULL
);

-- 6. Enforce Append-Only Immutability: Block UPDATE and DELETE on audit_logs
CREATE OR REPLACE RULE no_update_audit AS ON UPDATE TO audit_logs DO INSTEAD NOTHING;
CREATE OR REPLACE RULE no_delete_audit AS ON DELETE TO audit_logs DO INSTEAD NOTHING;

-- 7. Audit Ledger Table / View (Tamper-evident append-only ledger alias)
CREATE OR REPLACE VIEW audit_ledger AS SELECT * FROM audit_logs;