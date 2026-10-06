package socks5

import (
	"crypto/sha256"
	"crypto/subtle"
)

// CredentialStore is used to support user/pass authentication
type CredentialStore interface {
	Valid(user, password string) bool
}

// StaticCredentials enables using a map directly as a credential store
type StaticCredentials map[string]string

func (s StaticCredentials) Valid(user, password string) bool {
	if user == "" || password == "" {
		return false
	}
	pass, ok := s[user]
	if !ok {
		return false
	}
	providedHash := sha256.Sum256([]byte(password))
	storedHash := sha256.Sum256([]byte(pass))
	return subtle.ConstantTimeCompare(providedHash[:], storedHash[:]) == 1
}
