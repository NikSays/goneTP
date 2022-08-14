package core

import (
	"bytes"
	"crypto/md5"
	"encoding/gob"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const (
	defaultStoreFilename = "gonetp.store"
	aesBlockSize = 32
)

//Positions and lengths of file segments
const (
	magicString = "GOTP<3<3"
	magicStringLen = len(magicString)
	checksumPos = magicStringLen
	checksumLen = 16
	saltPos = checksumPos + checksumLen
	saltLen = 20 // salt + nonce = 32
	noncePos = saltPos + saltLen
	nonceLen = 12 // AES-GCM
	ciphertextPos = noncePos + nonceLen 
)

func getStorePath(providedPath string) (string, error) {
	if len(providedPath) == 0 {
		dir, err := os.UserConfigDir()
		if err != nil {
			return "", errors.New("getStorePath: Store path not provided, $HOME is not set")
		}
		storePath := filepath.Join(dir, "gonetp", defaultStoreFilename) 
		return storePath, nil
	}
	if providedPath == filepath.Dir(providedPath) {
		storePath := providedPath + defaultStoreFilename
		return storePath, nil
	}
	return providedPath, nil
}

func LoadStore(providedPath string, password []byte) (OTPstore, error){
	storePath, err := getStorePath(providedPath)
	if err != nil {
		return nil, fmt.Errorf("LoadStore: Couldn't get store path -> %w", err)
	}
	content, err := os.ReadFile(storePath)
	if err != nil {
		return nil, fmt.Errorf("LoadStore: Couldn't read store file -> %w", err)
	}
	if len(content) < ciphertextPos-1 {
		return nil, errors.New("LoadStore: Content too short")
	}
	magicBytes := content[:checksumPos]
	checksum := content[checksumPos:saltPos]
	salt := content[saltPos:noncePos]
	nonce := content[noncePos:ciphertextPos]
	ciphertext := content[ciphertextPos:]

	if magicString != string(magicBytes) {
		return nil, errors.New("LoadStore: Wrong file structure")
	}
	
	trueChecksum := md5.Sum(content[saltPos:]) 
	if !bytes.Equal(checksum, trueChecksum[:]) {
		return nil, errors.New("LoadStore: Wrong checksum")
	}
	key, err := kdf(password, salt)
	if err != nil {
		return nil, fmt.Errorf("LoadStore: Couldn't create key -> %w", err)
	}
	plaintext, err := decrypt(key, nonce, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("LoadStore: Couldn't decrypt store -> %w", err)
	}
	store := OTPstore{}
	decoder := gob.NewDecoder(bytes.NewBuffer(plaintext))
	err = decoder.Decode(&store)
	if err != nil {
		return nil, fmt.Errorf("LoadStore: Corrupted store data -> %w", err)
	}
	return store, nil
}

func SaveStore(providedPath string, store OTPstore, password []byte) error {
	storePath, err := getStorePath(providedPath)
	if err != nil {
		return fmt.Errorf("SaveStore: Couldn't get store path -> %w", err)
	}		
	encodedStore := bytes.NewBuffer([]byte{})
	encoder := gob.NewEncoder(encodedStore)
	encoder.Encode(store)
	plaintext := encodedStore.Bytes()

	salt, err := getRandomBytes(saltLen)
	if err != nil {
		return fmt.Errorf("SaveStore: Couldn't create salt -> %w", err)
	}
	key, err := kdf(password, salt)
	if err != nil {
		return fmt.Errorf("SaveStore: Couldn't create key -> %w", err)
	}
	ciphertext, nonce, err := encrypt(key, plaintext)
	if err != nil {
		return fmt.Errorf("SaveStore: Couldn't create salt -> %w", err)
	}

	checksumData := append(salt, nonce...)
	checksumData = append(checksumData, ciphertext...)
	
	checksum := md5.Sum(checksumData)
	magicBytes := []byte(magicString)

	filedata := append(magicBytes, checksum[:]...)
	filedata = append(filedata, salt...)
	filedata = append(filedata, nonce...)
	filedata = append(filedata, ciphertext...)
	err = os.MkdirAll(filepath.Dir(storePath), 0700)
	if err != nil {
		return fmt.Errorf("SaveStore: Couldn't create store folder -> %w", err)
	}
	err = os.WriteFile(storePath, filedata, 0600)
	if err != nil {
		return fmt.Errorf("SaveStore: Couldn't create store file -> %w", err)
	}
	return nil
}