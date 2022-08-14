package core

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"

	"golang.org/x/crypto/scrypt"
) 

var ErrWrongPassword = errors.New("wrong password")
func encrypt(key, plaintext []byte) (ciphertext, nonce []byte, err error) {
	c, err := aes.NewCipher(key)
	if err != nil {
			return nil, nil, fmt.Errorf("encrypt: Couldn't create cipher -> %w", err)
	}

	gcm, err := cipher.NewGCMWithNonceSize(c, nonceLen)
	if err != nil {
			return nil, nil, fmt.Errorf("encrypt: Couldn't create GCM -> %w", err)
	}

	nonce, err = getRandomBytes(nonceLen)
	if err != nil {
		return nil, nil, fmt.Errorf("encrypt: Couldn't create nonce -> %w", err)
	}
	ciphertext = gcm.Seal(nil, nonce, plaintext, nil)

	return ciphertext, nonce, nil
}

func decrypt(key, nonce, ciphertext []byte) ([]byte, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
			return nil, fmt.Errorf("decrypt: Couldn't create cipher -> %w", err)
	}

	gcm, err := cipher.NewGCMWithNonceSize(c, nonceLen)
	if err != nil {
			return nil, fmt.Errorf("decrypt: Couldn't create GCM -> %w", err)
	}


	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
			return nil, fmt.Errorf("decrypt: Couldn't decipher -> %w", ErrWrongPassword)
	}

	return plaintext, nil
}

// Key derivation funciton
func kdf(password, salt []byte) ([]byte, error) {
	key, err := scrypt.Key(password, salt, 32768, 8, 1, aesBlockSize)
	if err != nil {
		return nil, fmt.Errorf("KDF: Couldn't create key -> %w", err)
	}
	return key, nil
}

func getRandomBytes(size int) ([]byte, error){
	bytes := make([]byte, size)
	_, err := rand.Read(bytes)
	if err != nil {
		return nil, fmt.Errorf("getRandomBytes: Couldn't read random bytes -> %w", err)
	}
	return bytes, nil
}