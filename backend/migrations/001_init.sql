-- HuntMCP Phase 2: Initial Database Schema
-- Requires: PostgreSQL 16+ with pgvector extension

-- Enable extensions
CREATE EXTENSION IF NOT EXISTS vector;
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ============================================================
-- Writeups table: stores bug bounty writeups with vector embeddings
-- ============================================================
CREATE TABLE IF NOT EXISTS writeups (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    title TEXT NOT NULL,
    url TEXT DEFAULT '',
    vuln_class TEXT NOT NULL,
    target_tech TEXT[] DEFAULT '{}',
    bounty INTEGER DEFAULT 0,
    author TEXT DEFAULT '',
    content TEXT NOT NULL,
    embedding VECTOR(384),            -- 384-dim from all-MiniLM-L6-v2
    source_type TEXT DEFAULT 'manual', -- 'manual', 'api', 'batch', 'cron'
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_writeups_vuln_class ON writeups(vuln_class);
CREATE INDEX IF NOT EXISTS idx_writeups_created_at ON writeups(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_writeups_source_type ON writeups(source_type);

-- pgvector IVF index for similarity search
CREATE INDEX IF NOT EXISTS idx_writeups_embedding ON writeups
    USING ivfflat (embedding vector_cosine_ops)
    WITH (lists = 100);

-- ============================================================
-- Users table: authentication and role management
-- ============================================================
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email TEXT UNIQUE NOT NULL,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT DEFAULT 'user',           -- 'user', 'admin'
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);

-- ============================================================
-- Hunts table: per-target hunt history and findings
-- ============================================================
CREATE TABLE IF NOT EXISTS hunts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    target TEXT NOT NULL,
    tech_stack TEXT[] DEFAULT '{}',
    findings JSONB DEFAULT '[]',
    chains JSONB DEFAULT '[]',
    subdomains TEXT[] DEFAULT '{}',
    bounty_estimate TEXT DEFAULT '',
    summary TEXT DEFAULT '',
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    hunted_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_hunts_target ON hunts(target);
CREATE INDEX IF NOT EXISTS idx_hunts_user_id ON hunts(user_id);
CREATE INDEX IF NOT EXISTS idx_hunts_hunted_at ON hunts(hunted_at DESC);

-- ============================================================
-- Sample data (optional: run separately for development)
-- ============================================================
-- INSERT INTO users (email, username, password_hash, role)
-- VALUES ('admin@huntmcp.dev', 'admin', '$2a$10$...', 'admin');
