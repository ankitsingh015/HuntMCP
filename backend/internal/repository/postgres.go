package repository

import (
	"database/sql"
	"fmt"
	"log"
	"os"

	_ "github.com/lib/pq"
)

type DB struct {
	*sql.DB
}

func NewDB() (*DB, error) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		dsn = "postgres://huntmcp:huntmcp@localhost:5432/huntmcp?sslmode=disable"
	}

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)

	log.Printf("Connected to PostgreSQL: %s", maskDSN(dsn))
	return &DB{db}, nil
}

func (db *DB) RunMigrations() error {
	migrations := []string{
		`CREATE EXTENSION IF NOT EXISTS vector`,
		`CREATE EXTENSION IF NOT EXISTS "uuid-ossp"`,

		`CREATE TABLE IF NOT EXISTS writeups (
			id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
			title TEXT NOT NULL,
			url TEXT DEFAULT '',
			vuln_class TEXT NOT NULL,
			target_tech TEXT[] DEFAULT '{}',
			bounty INTEGER DEFAULT 0,
			author TEXT DEFAULT '',
			content TEXT NOT NULL,
			embedding VECTOR(384),
			source_type TEXT DEFAULT 'manual',
			created_at TIMESTAMPTZ DEFAULT NOW()
		)`,

		`CREATE TABLE IF NOT EXISTS users (
			id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
			email TEXT UNIQUE NOT NULL,
			username TEXT UNIQUE NOT NULL,
			password_hash TEXT NOT NULL,
			role TEXT DEFAULT 'user',
			created_at TIMESTAMPTZ DEFAULT NOW()
		)`,

		`CREATE TABLE IF NOT EXISTS hunts (
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
		)`,

		`CREATE INDEX IF NOT EXISTS idx_writeups_vuln_class ON writeups(vuln_class)`,
		`CREATE INDEX IF NOT EXISTS idx_writeups_created_at ON writeups(created_at DESC)`,
		`CREATE INDEX IF NOT EXISTS idx_hunts_target ON hunts(target)`,
		`CREATE INDEX IF NOT EXISTS idx_hunts_user_id ON hunts(user_id)`,
	}

	for _, m := range migrations {
		if _, err := db.Exec(m); err != nil {
			return fmt.Errorf("migration failed: %w\nSQL: %s", err, m[:60])
		}
	}

	log.Println("Migrations completed successfully")
	return nil
}

func maskDSN(dsn string) string {
	if len(dsn) > 40 {
		return dsn[:20] + "..." + dsn[len(dsn)-20:]
	}
	return dsn
}
