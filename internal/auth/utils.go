package auth

import (
	"strings"

	"github.com/google/uuid"
)

func newID() string {
	return uuid.New().String()
}

func splitSignedToken(signed string) []string {
	return strings.SplitN(signed, ".", 2)
}
