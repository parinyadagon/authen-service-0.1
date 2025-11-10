package mysql

import (
	"context"
	"testing"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

// Integration test - requires running MySQL database
func TestAuthRepository_Integration(t *testing.T) {
	// Skip if not running integration tests
	if testing.Short() {
		t.Skip("Skipping integration test")
	}

	// Connect to test database
	config := &Config{
		Host:     "localhost",
		Port:     3306,
		Username: "root",
		Password: "password",
		Database: "authen_db_test", // Use separate test database
	}

	db, err := NewConnection(config)
	if err != nil {
		t.Skipf("Failed to connect to test database: %v", err)
	}
	defer db.Close()

	repo := NewAuthRepository(db)
	ctx := context.Background()

	t.Run("FindRoleByName", func(t *testing.T) {
		// Test finding a role
		role, err := repo.FindRoleByName(ctx, "USER")
		if err != nil {
			t.Errorf("Expected to find USER role, got error: %v", err)
		}
		if role != nil && role.Name != "USER" {
			t.Errorf("Expected role name USER, got %s", role.Name)
		}
	})

	t.Run("IsEmailExists", func(t *testing.T) {
		// Test email existence check
		count, err := repo.IsEmailExists(ctx, "nonexistent@example.com")
		if err != nil {
			t.Errorf("Error checking email exists: %v", err)
		}
		if count != 0 {
			t.Errorf("Expected count 0 for nonexistent email, got %d", count)
		}
	})

	t.Run("IsUsernameExists", func(t *testing.T) {
		// Test username existence check
		count, err := repo.IsUsernameExists(ctx, "nonexistentuser")
		if err != nil {
			t.Errorf("Error checking username exists: %v", err)
		}
		if count != 0 {
			t.Errorf("Expected count 0 for nonexistent username, got %d", count)
		}
	})
}

// Unit test with mock database
func TestAuthRepository_Unit(t *testing.T) {
	// This would require a mocking library like sqlmock
	// For now, just test the helper functions

	t.Run("nullString helper", func(t *testing.T) {
		// Test empty string
		ns := nullString("")
		if ns.Valid {
			t.Error("Expected nullString(\"\") to be invalid")
		}

		// Test non-empty string
		ns = nullString("test")
		if !ns.Valid {
			t.Error("Expected nullString(\"test\") to be valid")
		}
		if ns.String != "test" {
			t.Errorf("Expected string value 'test', got '%s'", ns.String)
		}
	})

	t.Run("generateTokenID", func(t *testing.T) {
		id1 := generateTokenID()
		time.Sleep(1 * time.Millisecond) // Ensure different timestamp
		id2 := generateTokenID()

		if id1 == id2 {
			t.Error("Expected different token IDs")
		}

		if id1 == "" || id2 == "" {
			t.Error("Expected non-empty token IDs")
		}
	})
}

// Benchmark tests
func BenchmarkGenerateTokenID(b *testing.B) {
	for i := 0; i < b.N; i++ {
		generateTokenID()
	}
}

func BenchmarkNullString(b *testing.B) {
	for i := 0; i < b.N; i++ {
		nullString("test string")
	}
}
