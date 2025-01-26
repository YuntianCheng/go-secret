package test

import (
	"encoding/hex"
	"encoding/json"
	"go-secret/crypt"
	"go-secret/items"
	"go-secret/password"
	"go-secret/secret_file"
	"os"
	"testing"
)

func TestCrypt(t *testing.T) {
	pwd := "233233"
	pwd = password.PasswordToSha256(pwd)
	t.Log(pwd)
	login := items.Login{
		Username: "admin",
		Password: "123456",
	}
	vault := secret_file.Vault{
		Name:       "test",
		LoginItems: []items.Login{login},
	}
	file := secret_file.SecretFile{
		Vaults: []secret_file.Vault{vault},
	}
	json_file, err := json.Marshal(file)
	if err != nil {
		t.Error(err)
	}
	t.Log(string(json_file))
	pwdBytes, err := hex.DecodeString(pwd)
	if err != nil {
		t.Error(err)
	}
	secret := crypt.NewAES256([32]byte(pwdBytes))
	if err != nil {
		t.Error(err)
	}
	encrypted, err := secret.Encrypt(json_file)
	if err != nil {
		t.Error(err)
	}
	// t.Log(string(encrypted))
	filePath := "./test.secret"
	os.WriteFile(filePath, encrypted, 0644)

	data, err := os.ReadFile(filePath)
	if err != nil {
		t.Error(err)
	}
	// t.Log(string(data))
	decrypted, err := secret.Decrypt(data)
	if err != nil {
		t.Error(err)
	}
	t.Log(string(decrypted))
}
