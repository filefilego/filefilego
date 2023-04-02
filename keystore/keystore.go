package keystore

import (
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/filefilego/filefilego/common"
	"github.com/filefilego/filefilego/common/hexutil"
	"github.com/golang-jwt/jwt/v5"
)

const jwtValidityHours = 2160

// KeyLockUnlocker is an interface with locking and unlocking key functionality.
type KeyLockUnlocker interface {
	LockKey(address string, jwt string) (bool, error)
	UnlockKey(address string, passphrase string) (string, error)
}

// KeyAuthorizer is an interface with auth mechanism of a key.
type KeyAuthorizer interface {
	Authorized(jwtToken string) (bool, UnlockedKey, error)
}

// UnlockedKey represents an unlocked key with a jwt token.
type UnlockedKey struct {
	Key *Key
	JWT string
}

// Store handles keypair storage.
type Store struct {
	keysDir          string
	nodeIdentityData []byte
	unlockedKeys     map[string]UnlockedKey
	mu               sync.RWMutex
}

// New creates a new keystore.
func New(keysDir string, nodeIdentityData []byte) (*Store, error) {
	if keysDir == "" {
		return nil, errors.New("keysDir is empty")
	}

	if len(nodeIdentityData) == 0 {
		return nil, errors.New("nodeIdentityData is empty")
	}

	return &Store{
		keysDir:          keysDir,
		nodeIdentityData: nodeIdentityData,
		unlockedKeys:     make(map[string]UnlockedKey),
	}, nil
}

// CreateKey generates a new key.
func (ks *Store) CreateKey(passphrase string) (string, error) {
	if passphrase == "" {
		return "", errors.New("passphrase is empty")
	}
	key, err := NewKey()
	if err != nil {
		return "", fmt.Errorf("failed to create key: %w", err)
	}

	fileName, err := ks.SaveKey(key, passphrase)
	if err != nil {
		return "", err
	}

	return fileName, nil
}

// SaveKey saves a key given the passphrase.
func (ks *Store) SaveKey(key *Key, passphrase string) (string, error) {
	if passphrase == "" {
		return "", errors.New("passphrase is empty")
	}

	keyDataJSON, err := key.MarshalToJSON(passphrase)
	if err != nil {
		return "", fmt.Errorf("failed to marshal key: %w", err)
	}

	fileName, err := common.WriteToFile(keyDataJSON, filepath.Join(ks.keysDir, generateFilename(key.KeyPair.Address)))
	if err != nil {
		return "", fmt.Errorf("failed to write key to file: %v", err)
	}

	return fileName, nil
}

// LockKey removes the key from unlocked keys.
func (ks *Store) LockKey(address string, jwt string) (bool, error) {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	acc, ok := ks.unlockedKeys[address]
	if ok && acc.JWT == jwt {
		delete(ks.unlockedKeys, address)
		return true, nil
	}
	return false, fmt.Errorf("address %s not found", address)
}

// UnlockKey unlocks a key by address.
// it will try to unlock the node_identity_key first and if not then it will proceed with the keystore dir.
func (ks *Store) UnlockKey(address string, passphrase string) (string, error) {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	f, err := os.Open(ks.keysDir)
	if err != nil {
		return "", fmt.Errorf("failed to read keystore directory: %w", err)
	}
	fileInfo, err := f.Readdir(-1)
	f.Close()
	if err != nil {
		return "", fmt.Errorf("failed to read keystore directory: %w", err)
	}

	for _, file := range fileInfo {
		nodeIDKey := false
		if file.Name() == "node_identity.json" {
			nodeIDKey = true
			fileData, err := os.ReadFile(filepath.Join(ks.keysDir, file.Name()))
			if err != nil {
				continue
			}

			nodeIDAddress := hexutil.ExtractHex(string(fileData))
			if nodeIDAddress == "" {
				continue
			}
		} else {
			nodeIDKey = false
			fileNameContainsAddress := strings.Contains(file.Name(), address)
			if !fileNameContainsAddress {
				continue
			}
		}

		bts, err := os.ReadFile(path.Join(ks.keysDir, file.Name()))
		if err != nil {
			return "", fmt.Errorf("failed to read keystore file: %w", err)
		}

		key, err := UnmarshalKey(bts, passphrase)
		if nodeIDKey && err != nil {
			continue
		}

		if err != nil {
			return "", fmt.Errorf("failed to unmarshal keystore file: %w", err)
		}

		atClaims := jwt.MapClaims{}
		atClaims["address"] = key.Address
		atClaims["exp"] = time.Now().Add(time.Hour * jwtValidityHours).Unix()
		at := jwt.NewWithClaims(jwt.SigningMethodHS256, atClaims)
		token, err := at.SignedString(ks.nodeIdentityData)
		if err != nil {
			return "", fmt.Errorf("failed to sign jwt token with node's identity file: %w", err)
		}
		ks.unlockedKeys[key.Address] = UnlockedKey{
			Key: key,
			JWT: token,
		}
		return token, nil
	}

	return "", errors.New("key not found on this node")
}

// ListKeys lists the keys in the keysDir.
func (ks *Store) ListKeys() ([]string, error) {
	var files []string
	err := filepath.Walk(ks.keysDir, func(path string, info os.FileInfo, err error) error {
		if strings.Contains(path, "UTC") {
			prts := strings.Split(path, "--")
			files = append(files, prts[2])
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to read keys directory content: %w", err)
	}
	return files, nil
}

// Authorized checks if a token is authorized and valid.
func (ks *Store) Authorized(jwtToken string) (bool, UnlockedKey, error) {
	token, err := jwt.Parse(jwtToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return ks.nodeIdentityData, nil
	})
	if err != nil {
		return false, UnlockedKey{}, err
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return false, UnlockedKey{}, errors.New("token is invalid")
	}

	addr, addressFoundInJWT := claims["address"].(string)
	if !addressFoundInJWT {
		return false, UnlockedKey{}, errors.New("failed to extract address from jwt")
	}
	foundKey, found := ks.unlockedKeys[addr]
	if !found {
		return false, foundKey, errors.New("address is not unlocked")
	}
	return true, foundKey, nil
}
