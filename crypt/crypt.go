package crypt

type Crypt interface {
	// Encrypt encrypts the given text using the cryptography algorithm
	Encrypt(data []byte) ([]byte, error)
	// Decrypt decrypts the given base64 encoded encrypted text using the cryptography algorithm and returns the original data
	Decrypt(encryptedText []byte) ([]byte, error)
}
