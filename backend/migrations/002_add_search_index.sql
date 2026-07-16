-- HuntMCP: Additional search indexes for performance

-- Full-text search on writeups
CREATE INDEX IF NOT EXISTS idx_writeups_fts ON writeups
    USING GIN (to_tsvector('english', title || ' ' || content));

-- Composite index for common query patterns
CREATE INDEX IF NOT EXISTS idx_writeups_vuln_class_created
    ON writeups(vuln_class, created_at DESC);

-- Hunts: index on JSONB findings for common queries
CREATE INDEX IF NOT EXISTS idx_hunts_findings_gin
    ON hunts USING GIN (findings jsonb_path_ops);

-- Hunts: index on tech stack array
CREATE INDEX IF NOT EXISTS idx_hunts_tech_gin
    ON hunts USING GIN (tech_stack);

-- Vector similarity search with higher accuracy (IVF with more lists)
-- Run after data is populated: CREATE INDEX idx_writeups_embedding_hnsw
--     ON writeups USING hnsw (embedding vector_cosine_ops);
-- Note: HNSW is slower to build but faster to query than IVFFlat
