package service

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/ankitsingh015/HuntMCP/backend/internal/model"
)

const testJWTSecret = "test-secret-for-auth-service-unit-tests"

func newTestAuthService(t *testing.T) *AuthService {
	t.Helper()
	t.Setenv("JWT_SECRET", testJWTSecret)
	return NewAuthService(nil)
}

func TestGenerateAndValidateToken_RoundTrip(t *testing.T) {
	s := newTestAuthService(t)
	user := model.User{ID: "user-123", Username: "alice", Role: "user"}

	token, err := s.generateToken(user)
	if err != nil {
		t.Fatalf("generateToken: %v", err)
	}

	claims, err := s.ValidateToken(token)
	if err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}
	if claims.UserID != user.ID {
		t.Errorf("UserID = %q, want %q", claims.UserID, user.ID)
	}
	if claims.Username != user.Username {
		t.Errorf("Username = %q, want %q", claims.Username, user.Username)
	}
	if claims.Role != user.Role {
		t.Errorf("Role = %q, want %q", claims.Role, user.Role)
	}
}

// A validly-signed token whose claims have the wrong type (e.g. a numeric
// user_id) must return an error, not panic -- this is the bug the unchecked
// type assertions in ValidateToken used to have.
func TestValidateToken_WrongClaimType(t *testing.T) {
	s := newTestAuthService(t)

	claims := jwt.MapClaims{
		"user_id":  12345, // wrong type: should be a string
		"username": "alice",
		"role":     "user",
		"exp":      time.Now().Add(time.Hour).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString([]byte(testJWTSecret))
	if err != nil {
		t.Fatalf("sign test token: %v", err)
	}

	if _, err := s.ValidateToken(signed); err == nil {
		t.Fatal("ValidateToken with wrong-typed user_id claim: want error, got nil")
	}
}

func TestValidateToken_MissingClaim(t *testing.T) {
	s := newTestAuthService(t)

	claims := jwt.MapClaims{
		"user_id": "user-123",
		// username and role omitted
		"exp": time.Now().Add(time.Hour).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString([]byte(testJWTSecret))
	if err != nil {
		t.Fatalf("sign test token: %v", err)
	}

	if _, err := s.ValidateToken(signed); err == nil {
		t.Fatal("ValidateToken with missing username/role claims: want error, got nil")
	}
}

func TestValidateToken_WrongSigningMethod(t *testing.T) {
	s := newTestAuthService(t)

	claims := jwt.MapClaims{
		"user_id":  "user-123",
		"username": "alice",
		"role":     "user",
		"exp":      time.Now().Add(time.Hour).Unix(),
	}
	// "none" algorithm tokens must always be rejected -- ValidateToken only
	// trusts *jwt.SigningMethodHMAC.
	token := jwt.NewWithClaims(jwt.SigningMethodNone, claims)
	signed, err := token.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("sign none-alg test token: %v", err)
	}

	if _, err := s.ValidateToken(signed); err == nil {
		t.Fatal("ValidateToken with alg=none token: want error, got nil")
	}
}
