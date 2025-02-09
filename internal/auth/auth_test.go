package auth

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestHashPassword(t *testing.T) {
	password := "password"
	_, err := HashPassword(password)
	if err != nil {
		t.Fatalf("Error hashing password: %s", err)
	}
}

func TestCheckPasswordHash(t *testing.T) {
	password := "password"
	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("Error hashing password: %s", err)
	}

	err = CheckPasswordHash(password, hash)
	if err != nil {
		t.Fatalf("Error checking password hash: %s", err)
	}
}

// func MakeJWT(userID uuid.UUID, tokenSecret string, expiresIn time.Duration) (string, error) {
// func ValidateJWT(tokenString, tokenSecret string) (uuid.UUID, error) {

func TestJWT(t *testing.T) {

	userID := uuid.New()
	tokenSecret := "secret"
	expiresIn := 3600 * time.Second
	jwtStr, err := MakeJWT(userID, tokenSecret, expiresIn)
	if err != nil {
		t.Fatalf("Error making JWT: %s", err)
	}

	id, err := ValidateJWT(jwtStr, tokenSecret)
	if err != nil {
		t.Fatalf("Error validating JWT: %s", err)
	}

	if id != userID {
		t.Fatalf("Expected %s, got %s", userID, id)
	}

}
