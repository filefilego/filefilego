package binlayer

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path"
	"time"

	"github.com/boltdb/bolt"
	"github.com/filefilego/filefilego/common"
)

var (
	tokensBucket    = "tokens"
	dataBucket      = "data"
	fileHashBugcket = "fhashes"
)

// AddressToken represents
type AddressToken struct {
	AccessType string `json:"access_type"`
	Token      string `json:"token"`
	ExpiresAt  int64  `json:"expires_at"`
}

// Engine represents the storage layer
type Engine struct {
	DownloadPath string
	Path         string
	Enabled      bool
	DB           *bolt.DB
	FeesPerGB    string
}

func createDirectory(path string) error {
	src, err := os.Stat(path)
	if os.IsNotExist(err) {
		errDir := os.MkdirAll(path, 0755)
		if errDir != nil {
			return err
		}
		return nil
	}

	if src.Mode().IsRegular() {
		return errors.New("binlayerdir is a file")
	}

	return nil
}

// NewEngine returns an instance of engine
func NewEngine(downloadPath, path, dataDir, token, feesGB string) (Engine, error) {

	filePath := dataDir + "/db/binlayer.db"
	if !common.FileExists(filePath) {
		os.MkdirAll(dataDir+"/db/", os.ModePerm)
	}

	db, err := bolt.Open(filePath, 0600, nil)
	if err != nil {
		log.Panic(err)
	}

	err = db.Update(func(tx *bolt.Tx) error {
		tx.CreateBucketIfNotExists([]byte(tokensBucket))
		tx.CreateBucketIfNotExists([]byte(dataBucket))
		tx.CreateBucketIfNotExists([]byte(fileHashBugcket))
		return nil
	})

	ng := Engine{Path: path, DB: db, FeesPerGB: feesGB, DownloadPath: downloadPath}

	ng.InsertToken(token, "admin")

	if !common.DirExists(path) {
		err := createDirectory(path)
		if err != nil {
			log.Fatal(err)
		}
	}

	if !common.DirExists(downloadPath) {
		err := createDirectory(downloadPath)
		if err != nil {
			log.Fatal(err)
		}
	}

	return ng, nil
}

// MakeFolderPartitions makes folders with current date inside the binlayerdir path
func (n *Engine) MakeFolderPartitions() (string, error) {
	currentTime := time.Now()
	folder := fmt.Sprintf("%d-%02d-%02d", currentTime.Year(), currentTime.Month(), currentTime.Day())

	destinationPath := path.Join(n.Path, folder)

	createDirectory(destinationPath)

	return destinationPath, nil
}

// Search for a file hash
func (n *Engine) Search(query string) (string, error) {
	return "", nil
}

// Can checks if a token is allowed, return if allowed, access type, and error
func (n *Engine) Can(token string) (bool, string, error) {
	act := AddressToken{}

	err := n.DB.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(tokensBucket))
		bts := b.Get([]byte(token))
		if bts == nil {
			return errors.New("Token not registered")
		}

		err := json.Unmarshal(bts, &act)
		if err != nil {
			return err
		}

		if time.Now().Unix() > act.ExpiresAt {
			return errors.New("Token expired")
		}

		return nil
	})

	if err != nil {
		return false, act.AccessType, err
	}

	return true, act.AccessType, nil
}

// InsertToken inserts a token into db
func (n *Engine) InsertToken(token string, accessType string) error {
	err := n.DB.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(tokensBucket))
		act := AddressToken{
			AccessType: accessType,
			Token:      token,
			ExpiresAt:  time.Now().Add(time.Hour * 2160).Unix(), // 90 days
		}
		bts, err := json.Marshal(&act)
		if err != nil {
			return err
		}
		b.Put([]byte(token), bts)
		return nil
	})

	return err
}

// FileHashExists checks if a hash exists and returns the NodeHash bucket address
func (n *Engine) FileHashExists(fileHash string) (bool, string) {
	nodeHash := ""
	err := n.DB.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(fileHashBugcket))
		node := b.Get([]byte(fileHash))
		if node == nil {
			return errors.New("Node doesnt exists")
		}
		nodeHash = string(node)
		return nil
	})

	if err != nil {
		return false, ""
	}

	return true, nodeHash
}

// InsertBinaryItem inserts metadat to db
func (n *Engine) InsertBinaryItem(nodeHash string, data []byte, fileHash string, fileHashExistsInDb bool) error {
	err := n.DB.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(dataBucket))
		node := b.Get([]byte(nodeHash))
		if node != nil {
			return errors.New("node hash already exists, try to rename")
		}
		b.Put([]byte(nodeHash), data)

		if !fileHashExistsInDb {
			// put in the
			c := tx.Bucket([]byte(fileHashBugcket))
			c.Put([]byte(fileHash), []byte(nodeHash))
		}
		return nil
	})

	return err
}

// GetBinaryItem gets data of binaryitem
func (n *Engine) GetBinaryItem(nodeHash string) ([]byte, error) {
	var data []byte
	err := n.DB.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(dataBucket))
		node := b.Get([]byte(nodeHash))
		data = make([]byte, len(node))
		if node == nil {
			return errors.New("Node hash doesn't exist")
		}
		// copy
		copy(data, node)
		return nil
	})
	if err != nil {
		return data, err
	}

	return data, nil
}
