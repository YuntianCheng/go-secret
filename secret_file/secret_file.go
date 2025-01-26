package secret_file

import "go-secret/items"

type Vault struct {
	Name       string        `json:"name"`
	LoginItems []items.Login `json:"login_items"`
}

type SecretFile struct {
	Vaults []Vault `json:"vaults"`
}
