package crypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
)

type AES256 struct {
	Key [32]byte
}

func NewAES256(key [32]byte) *AES256 {
	return &AES256{
		Key: key,
	}
}

// getKey 获取AES加密块
func (c *AES256) getKey() (cipher.Block, error) {
	// 使用AES-256创建加密块
	return aes.NewCipher(c.Key[:])
}

// Encrypt 加密文本
func (c *AES256) Encrypt(plainData []byte) ([]byte, error) {
	block, err := c.getKey()
	if err != nil {
		return nil, err
	}

	// 创建初始化向量, 长度为16字节
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	// 创建加密器
	encrypter := cipher.NewCBCEncrypter(block, iv)

	// PKCS7填充
	padding := aes.BlockSize - (len(plainData) % aes.BlockSize)
	padText := make([]byte, len(plainData)+padding)
	copy(padText, plainData)
	for i := len(plainData); i < len(padText); i++ {
		padText[i] = byte(padding)
	}

	// 加密
	ciphertext := make([]byte, len(padText))
	encrypter.CryptBlocks(ciphertext, padText)

	// 将IV和密文组合
	final := make([]byte, len(iv)+len(ciphertext))
	copy(final, iv)
	copy(final[len(iv):], ciphertext)

	return final, nil
}

// Decrypt 解密文本
func (c *AES256) Decrypt(data []byte) ([]byte, error) {
	block, err := c.getKey()
	if err != nil {
		return nil, err
	}

	if len(data) < aes.BlockSize {
		return nil, errors.New("密文太短")
	}

	// 提取IV
	iv := data[:aes.BlockSize]
	msg := data[aes.BlockSize:]

	if len(msg) == 0 || len(msg)%aes.BlockSize != 0 {
		return nil, errors.New("密文长度不正确")
	}

	// 创建解密器
	decrypter := cipher.NewCBCDecrypter(block, iv)

	// 解密
	plaintext := make([]byte, len(msg))
	decrypter.CryptBlocks(plaintext, msg)

	// 去除PKCS7填充
	padding := int(plaintext[len(plaintext)-1])
	if padding > aes.BlockSize || padding == 0 {
		return nil, errors.New("无效的填充")
	}

	for i := len(plaintext) - padding; i < len(plaintext); i++ {
		if plaintext[i] != byte(padding) {
			return nil, errors.New("无效的填充")
		}
	}

	return plaintext[:len(plaintext)-padding], nil
}
