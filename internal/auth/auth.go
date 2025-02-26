package auth

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

func HashPassword(password string) (string, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	if err != nil {
		return "", err
	}

	return string(hashedPassword), nil
}

func CheckPasswordHash(password, hash string) error {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	if err != nil {
		return err
	}
	return nil
}

/*
Use jwt.NewWithClaims to create a new token.
Use jwt.SigningMethodHS256 as the signing method.
Use jwt.RegisteredClaims as the claims.
Set the Issuer to “chirpy”
Set IssuedAt to the current time in UTC
Set ExpiresAt to the current time plus the expiration time (expiresIn)
Set the Subject to a stringified version of the user’s id
Use token.SignedString to sign the token with the secret key. Refer to here for an overview of the different signing methods and their respective key types.
*/

func MakeJWT(userID uuid.UUID, tokenSecret string) (string, error) {
	expiresIn := 1 * time.Hour
	claims := jwt.RegisteredClaims{
		Issuer:    "chirpy",
		IssuedAt:  jwt.NewNumericDate(time.Now().UTC()),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(expiresIn).UTC()),
		Subject:   userID.String(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(tokenSecret))
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

/*
Use the jwt.ParseWithClaims function to validate the signature of the JWT and extract the claims into a *jwt.Token struct.
An error will be returned if the token is invalid or has expired.

If all is well with the token, use the token.Claims interface to get access to the user’s id from the claims (which should be stored in the Subject field).
Return the id as a uuid.UUID.

*/

func ValidateJWT(tokenString, tokenSecret string) (uuid.UUID, error) {
	token, err := jwt.ParseWithClaims(tokenString, jwt.MapClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(tokenSecret), nil
	})

	if err != nil {
		return uuid.Nil, err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return uuid.Nil, err
	}

	userID, err := uuid.Parse(claims["sub"].(string))
	if err != nil {
		return uuid.Nil, err
	}

	return userID, nil
}

/*
This function should look for the Authorization header in the headers parameter and return the TOKEN_STRING
if it exists (stripping off the Bearer prefix and whitespace). If the header doesn’t exist, return an error.
This is an easy one to write a unit test for, and I’d recommend doing so.
*/

func GetBearerToken(headers http.Header) (string, error) {
	authHeader := headers.Get("Authorization")
	if authHeader == "" {
		return "", errors.New("authorization header is missing")
	}

	authHeaderParts := strings.Split(authHeader, " ")
	if len(authHeaderParts) != 2 {
		return "", errors.New("authorization header is invalid")
	}

	if authHeaderParts[0] != "Bearer" {
		return "", errors.New("authorization header is not a Bearer token")
	}

	return authHeaderParts[1], nil
}

func MakeRefreshToken() (string, error) {
	token := make([]byte, 32)
	_, err := rand.Read(token)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(token), nil
}

func GetAPIKey(headers http.Header) (string, error) {
	authHeader := headers.Get("Authorization")
	if authHeader == "" {
		return "", errors.New("authorization header is missing")
	}

	authHeaderParts := strings.Split(authHeader, " ")
	if len(authHeaderParts) != 2 {
		return "", errors.New("authorization header is invalid")
	}

	if authHeaderParts[0] != "ApiKey" {
		return "", errors.New("authorization header is not an API Key")
	}

	return authHeaderParts[1], nil

}
