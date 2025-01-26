package password

import (
	"crypto/sha256"
	"encoding/hex"
)

func PasswordToSha256(password string) string {
	hash := sha256.New()
	hash.Write([]byte(password))
	return hex.EncodeToString(hash.Sum(nil))
}
