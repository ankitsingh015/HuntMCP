package repository

import "testing"

// NewDB must fail closed when DATABASE_URL is unset instead of silently
// falling back to a hardcoded local DSN.
func TestNewDB_FailsClosedWithoutDatabaseURL(t *testing.T) {
	t.Setenv("DATABASE_URL", "")

	if _, err := NewDB(); err == nil {
		t.Fatal("NewDB with DATABASE_URL unset: want error, got nil")
	}
}
