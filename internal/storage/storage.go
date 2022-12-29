package storage

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"time"

	"github.com/filefilego/filefilego/internal/common"
	"github.com/filefilego/filefilego/internal/common/hexutil"
	"github.com/filefilego/filefilego/internal/crypto"
	"github.com/filefilego/filefilego/internal/database"
	log "github.com/sirupsen/logrus"
)

const (
	tokenAccessHours = 2160

	// AdminAccess represents full access.
	AdminAccess = "admin"
	// UserAccess represents priviledge access.
	UserAccess = "user"
)

// FileMetadata holds the metadata for a file.
type FileMetadata struct {
	Hash     string `json:"hash"`
	FilePath string `json:"file_path"`
	Size     int64  `json:"size"`
}

// AccessToken represents an access token.
type AccessToken struct {
	AccessType string `json:"access_type"`
	Token      string `json:"token"`
	ExpiresAt  int64  `json:"expires_at"`
}

// Storage represents the storage engine and the metadata.
type Storage struct {
	db          database.Database
	storagePath string
	enabled     bool
}

// New creates a new storage instance.
func New(db database.Database, storagePath string, enabled bool, adminToken string) (*Storage, error) {
	if db == nil {
		return nil, errors.New("db is nil")
	}

	if storagePath == "" {
		return nil, errors.New("storagePath is empty")
	}

	if adminToken == "" {
		return nil, errors.New("adminToken is empty")
	}

	if !common.DirExists(storagePath) {
		err := common.CreateDirectory(storagePath)
		if err != nil {
			return nil, fmt.Errorf("failed to create storage directory: %w", err)
		}
	}

	storage := &Storage{
		db:          db,
		storagePath: storagePath,
		enabled:     enabled,
	}

	token := AccessToken{
		AccessType: AdminAccess,
		Token:      adminToken,
		ExpiresAt:  time.Now().Add(time.Hour * tokenAccessHours).Unix(),
	}

	err := storage.SaveToken(token)
	if err != nil {
		return nil, fmt.Errorf("failed to save admin token: %w", err)
	}

	return storage, nil
}

// StoragePath return the storage path.
func (s *Storage) StoragePath() string {
	return s.storagePath
}

// Enabled return if storage functionality is enabled.
func (s *Storage) Enabled() bool {
	return s.enabled
}

// SetEnabled return if storage functionality is enabled.
func (s *Storage) SetEnabled(val bool) {
	s.enabled = val
}

// CreateSubfolders creates sub folders with current date inside the data directory.
func (s *Storage) CreateSubfolders() (string, error) {
	currentTime := time.Now()
	folder := fmt.Sprintf("%d-%02d-%02d", currentTime.Year(), currentTime.Month(), currentTime.Day())
	destinationPath := path.Join(s.storagePath, folder)
	err := common.CreateDirectory(destinationPath)
	if err != nil {
		return "", err
	}
	return destinationPath, nil
}

// SaveToken saves an access token into the database.
func (s *Storage) SaveToken(token AccessToken) error {
	if token.Token == "" || token.AccessType == "" || token.ExpiresAt == 0 {
		return errors.New("invalid access token")
	}
	data, err := json.Marshal(&token)
	if err != nil {
		return fmt.Errorf("failed to marshal access token: %w", err)
	}
	return s.db.Put([]byte(token.Token), data)
}

// SaveFileMetadata saves a file's metadata in the database.
func (s *Storage) SaveFileMetadata(nodeHash string, metadata FileMetadata) error {
	if metadata.FilePath == "" || metadata.Hash == "" || metadata.Size == 0 {
		return errors.New("invalid file metadata")
	}

	data, err := json.Marshal(&metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal file metadata: %w", err)
	}

	err = s.db.Put([]byte(nodeHash), data)
	if err != nil {
		return fmt.Errorf("failed to insert nodeHash %s", nodeHash)
	}

	err = s.db.Put([]byte(metadata.Hash), []byte(nodeHash))
	if err != nil {
		return fmt.Errorf("failed to insert fileHash %s", metadata.Hash)
	}
	return nil
}

// GetFileMetadata gets a file's metadata in the database.
func (s *Storage) GetFileMetadata(nodeHash string) (FileMetadata, error) {
	if nodeHash == "" {
		return FileMetadata{}, errors.New("nodeHash is empty")
	}
	data, err := s.db.Get([]byte(nodeHash))
	if err != nil {
		return FileMetadata{}, fmt.Errorf("failed to get file metadata: %w", err)
	}
	metadata := FileMetadata{}
	err = json.Unmarshal(data, &metadata)
	if err != nil {
		return FileMetadata{}, fmt.Errorf("failed to unmarshal file metadata: %w", err)
	}
	return metadata, nil
}

// GetNodeHashFromFileHash gets the node's Hash given a fileHash.
func (s *Storage) GetNodeHashFromFileHash(fileHash string) (string, bool) {
	if fileHash == "" {
		return "", false
	}
	nodeData, err := s.db.Get([]byte(fileHash))
	if err != nil {
		return "", false
	}
	return string(nodeData), true
}

// CanAccess authorizes access.
func (s *Storage) CanAccess(token string) (bool, AccessToken, error) {
	if token == "" {
		return false, AccessToken{}, errors.New("token is empty")
	}

	data, err := s.db.Get([]byte(token))
	if err != nil {
		return false, AccessToken{}, err
	}

	accToken := AccessToken{}
	err = json.Unmarshal(data, &accToken)
	if err != nil {
		return false, AccessToken{}, fmt.Errorf("failed to unmarshal access token: %w", err)
	}

	if time.Now().Unix() > accToken.ExpiresAt {
		return false, AccessToken{}, errors.New("access token is expired")
	}

	return true, accToken, nil
}

func writeHeaderPayload(w http.ResponseWriter, status int, payload string) {
	w.WriteHeader(status)
	// nolint:errcheck
	w.Write([]byte(payload))
}

// ServeHTTP handles file uploading.
func (s *Storage) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
	w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")

	if r.Method == "OPTIONS" {
		return
	}

	if !s.enabled {
		writeHeaderPayload(w, http.StatusForbidden, `{"error": "storage is not enabled"}`)
		return
	}

	if r.Method != "POST" {
		writeHeaderPayload(w, http.StatusMethodNotAllowed, `{"error": "method not available"}`)
		return
	}

	can, _, err := s.CanAccess(r.Header.Get("Authorization"))
	if !can {
		writeHeaderPayload(w, http.StatusForbidden, `{"error": "`+err.Error()+`"}`)
		return
	}

	reader, err := r.MultipartReader()
	if err != nil {
		writeHeaderPayload(w, http.StatusInternalServerError, `{"error": "`+err.Error()+`"}`)
		return
	}

	folderPath, err := s.CreateSubfolders()
	if err != nil {
		writeHeaderPayload(w, http.StatusInternalServerError, `{"error": "`+err.Error()+`"}`)
		return
	}

	nodeHash := ""
	tmpFileHex := ""
	for {
		part, err := reader.NextPart()
		if err == io.EOF {
			// done reading body
			break
		}

		formName := part.FormName()
		if formName == "node_hash" {
			nodeHashData, err := io.ReadAll(part)
			if err != nil {
				log.Warnf("failed to read: %v", err)
			}
			nodeHash = string(nodeHashData)
			continue
		}

		if formName == "file" {
			tmpFileName, err := crypto.RandomEntropy(40)
			if err != nil {
				writeHeaderPayload(w, http.StatusInternalServerError, `{"error": "`+err.Error()+`"}`)
				return
			}

			tmpFileHex = hexutil.Encode(tmpFileName)
			destFile, err := os.Create(path.Join(folderPath, tmpFileHex))
			if err != nil {
				writeHeaderPayload(w, http.StatusInternalServerError, `{"error": "failed to open file on the system"}`)
				return
			}
			_, err = io.Copy(destFile, part)
			if err != nil {
				writeHeaderPayload(w, http.StatusInternalServerError, `{"error": "failed to copy from multipart reader"}`)
				return
			}
		}
		// part.Close()
	}

	old := path.Join(folderPath, tmpFileHex)
	fileSize, err := common.FileSize(old)
	if err != nil {
		os.Remove(old)
		writeHeaderPayload(w, http.StatusInternalServerError, `{"error": "failed to get file's size"}`)
		return
	}

	newPath := path.Join(folderPath, nodeHash)
	err = os.Rename(old, newPath)
	if err != nil {
		os.Remove(old)
		writeHeaderPayload(w, http.StatusInternalServerError, `{"error": "failed to rename file to node hash"}`)
		return
	}

	fHash, err := common.Sha1File(newPath)
	if err != nil {
		os.Remove(newPath)
		writeHeaderPayload(w, http.StatusInternalServerError, `{"error": "failed to hash contents of file"}`)
		return
	}

	fileMetadata := FileMetadata{
		Hash:     fHash,
		FilePath: folderPath,
		Size:     fileSize,
	}

	nodeHashDB, fileHashExistsInDB := s.GetNodeHashFromFileHash(fHash)
	if fileHashExistsInDB {
		fileMetadata, err = s.GetFileMetadata(nodeHashDB)
		if err != nil {
			os.Remove(newPath)
			writeHeaderPayload(w, http.StatusInternalServerError, `{"error": "`+err.Error()+`"}`)
			return
		}
	}
	err = s.SaveFileMetadata(nodeHash, fileMetadata)
	if err != nil {
		os.Remove(newPath)
		writeHeaderPayload(w, http.StatusInternalServerError, `{"error": "`+err.Error()+`"}`)
		return
	}

	writeHeaderPayload(w, http.StatusOK, fmt.Sprintf(`{"file_hash": "%s", "size": %d}`, fileMetadata.Hash, fileMetadata.Size))
}

// Authenticate authenticates storage access.
func (s *Storage) Authenticate(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
	w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")

	if r.Method == "OPTIONS" {
		return
	}

	if !s.enabled {
		writeHeaderPayload(w, http.StatusForbidden, `{"error": "storage is not enabled"}`)
		return
	}

	if r.Method != "POST" {
		writeHeaderPayload(w, http.StatusMethodNotAllowed, `{"error": "method not available"}`)
		return
	}

	can, accessToken, err := s.CanAccess(r.Header.Get("Authorization"))
	if !can {
		writeHeaderPayload(w, http.StatusForbidden, `{"error": "`+err.Error()+`"}`)
		return
	}

	if accessToken.AccessType != AdminAccess {
		writeHeaderPayload(w, http.StatusUnauthorized, `{"error": "not authorized to perform this operation"}`)
		return
	}

	randomBytes, err := crypto.RandomEntropy(60)
	if err != nil {
		writeHeaderPayload(w, http.StatusInternalServerError, `{"error": "`+err.Error()+`"}`)
		return
	}

	// create a user token
	token := AccessToken{
		AccessType: UserAccess,
		Token:      hexutil.Encode(randomBytes),
		ExpiresAt:  time.Now().Add(time.Hour * tokenAccessHours).Unix(),
	}

	err = s.SaveToken(token)
	if err != nil {
		writeHeaderPayload(w, http.StatusInternalServerError, `{"error": "`+err.Error()+`"}`)
		return
	}

	writeHeaderPayload(w, http.StatusOK, `{"token": "`+token.Token+`"}`)
}
