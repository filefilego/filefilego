package storage

import (
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/filefilego/filefilego/common"
	"github.com/filefilego/filefilego/common/hexutil"
	"github.com/filefilego/filefilego/crypto"
	"github.com/filefilego/filefilego/database"
	log "github.com/sirupsen/logrus"
)

const (

	// AdminAccess represents full access.
	AdminAccess = "admin"
	// UserAccess represents priviledge access.
	UserAccess = "user"

	tokenAccessHours = 2160
	tokenPrefix      = "token"
	fileHashPrefix   = "mdt"

	fileHashToNodePrefix = "fhn"
)

// Interface defines the functionalities of the storage engine.
type Interface interface {
	StoragePath() string
	Enabled() bool
	SetEnabled(val bool)
	CreateSubfolders() (string, error)
	SaveToken(token AccessToken) error
	SaveFileMetadata(nodeHash, fileHash string, metadata FileMetadata) error
	GetFileMetadata(fileHash string) (FileMetadata, error)
	GetNodeHashFromFileHash(fileHash string) (string, bool)
	CanAccess(token string) (bool, AccessToken, error)
}

// FileMetadata holds the metadata for a file.
type FileMetadata struct {
	FileName       string `json:"file_name"`
	MerkleRootHash string `json:"merkle_root_hash"`
	Hash           string `json:"hash"`
	FilePath       string `json:"file_path"`
	Size           int64  `json:"size"`
}

// AccessToken represents an access token.
type AccessToken struct {
	AccessType string `json:"access_type"`
	Token      string `json:"token"`
	ExpiresAt  int64  `json:"expires_at"`
}

// Storage represents the storage engine and the metadata.
type Storage struct {
	db                      database.Database
	storagePath             string
	enabled                 bool
	merkleTreeTotalSegments int
}

// New creates a new storage instance.
func New(db database.Database, storagePath string, enabled bool, adminToken string, merkleTreeTotalSegments int) (*Storage, error) {
	if db == nil {
		return nil, errors.New("db is nil")
	}

	if storagePath == "" {
		return nil, errors.New("storagePath is empty")
	}

	if adminToken == "" {
		return nil, errors.New("adminToken is empty")
	}

	if merkleTreeTotalSegments == 0 {
		return nil, errors.New("merkle tree total segments is zero")
	}

	if !common.DirExists(storagePath) {
		if err := common.CreateDirectory(storagePath); err != nil {
			return nil, fmt.Errorf("failed to create storage directory: %w", err)
		}
	}

	storage := &Storage{
		db:                      db,
		storagePath:             storagePath,
		enabled:                 enabled,
		merkleTreeTotalSegments: merkleTreeTotalSegments,
	}

	token := AccessToken{
		AccessType: AdminAccess,
		Token:      adminToken,
		ExpiresAt:  time.Now().Add(time.Hour * tokenAccessHours).Unix(),
	}

	if err := storage.SaveToken(token); err != nil {
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
	destinationPath := filepath.Join(s.storagePath, folder)
	if err := common.CreateDirectory(destinationPath); err != nil {
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

	return s.db.Put(append([]byte(tokenPrefix), []byte(token.Token)...), data)
}

// SaveFileMetadata saves a file's metadata in the database.
func (s *Storage) SaveFileMetadata(nodeHash, fileHash string, metadata FileMetadata) error {
	if metadata.MerkleRootHash == "" || metadata.FilePath == "" || metadata.Hash == "" || metadata.Size == 0 {
		return errors.New("invalid file metadata")
	}

	data, err := json.Marshal(&metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal file metadata: %w", err)
	}

	err = s.db.Put(append([]byte(fileHashPrefix), []byte(fileHash)...), data)
	if err != nil {
		return fmt.Errorf("failed to insert nodeHash %s", fileHash)
	}

	if nodeHash != "" {
		err = s.db.Put(append([]byte(fileHashToNodePrefix), []byte(metadata.Hash)...), []byte(nodeHash))
		if err != nil {
			return fmt.Errorf("failed to insert fileHash %s", metadata.Hash)
		}
	}

	return nil
}

// GetFileMetadata gets a file's metadata in the database.
func (s *Storage) GetFileMetadata(fileHash string) (FileMetadata, error) {
	if fileHash == "" {
		return FileMetadata{}, errors.New("file hash is empty")
	}
	data, err := s.db.Get(append([]byte(fileHashPrefix), []byte(fileHash)...))
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

	nodeData, err := s.db.Get(append([]byte(fileHashToNodePrefix), []byte(fileHash)...))
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

	data, err := s.db.Get(append([]byte(tokenPrefix), []byte(token)...))
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
	fileName := ""
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
				log.Warnf("failed to read from multipart: %v", err)
			}
			nodeHash = string(nodeHashData)
			continue
		}

		if formName == "file" {
			fileName = part.FileName()
			tmpFileName, err := crypto.RandomEntropy(40)
			if err != nil {
				writeHeaderPayload(w, http.StatusInternalServerError, `{"error": "`+err.Error()+`"}`)
				return
			}

			tmpFileHex = hexutil.Encode(tmpFileName)
			destFile, err := os.Create(filepath.Join(folderPath, tmpFileHex))
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
		part.Close()
	}

	if !validateFileName(fileName) {
		if err != nil {
			writeHeaderPayload(w, http.StatusInternalServerError, `{"error": "file name is invalid"}`)
			return
		}
	}

	old := filepath.Join(folderPath, tmpFileHex)
	fileSize, err := common.FileSize(old)
	if err != nil {
		os.Remove(old)
		writeHeaderPayload(w, http.StatusInternalServerError, `{"error": "failed to get file's size"}`)
		return
	}

	fHash, err := crypto.Sha1File(old)
	if err != nil {
		os.Remove(old)
		writeHeaderPayload(w, http.StatusInternalServerError, `{"error": "failed to hash contents of file"}`)
		return
	}

	newPath := filepath.Join(folderPath, fHash)
	err = os.Rename(old, newPath)
	if err != nil {
		log.Errorf("failed to move uploaded file: %v", err)
		os.Remove(old)
		writeHeaderPayload(w, http.StatusInternalServerError, `{"error": "failed to move uploaded file"}`)
		return
	}

	howManySegments, _, _, _ := common.FileSegmentsInfo(int(fileSize), s.merkleTreeTotalSegments, 0)
	orderedSlice := make([]int, howManySegments)
	for i := 0; i < howManySegments; i++ {
		orderedSlice[i] = i
	}

	fMerkleRootHash, err := common.GetFileMerkleRootHash(newPath, s.merkleTreeTotalSegments, orderedSlice)
	if err != nil {
		os.Remove(old)
		writeHeaderPayload(w, http.StatusInternalServerError, `{"error": "failed to get merkle root hash"}`)
		return
	}

	fileName = html.EscapeString(fileName)
	fileMetadata := FileMetadata{
		FileName:       fileName,
		MerkleRootHash: hexutil.Encode(fMerkleRootHash),
		Hash:           fHash,
		FilePath:       newPath,
		Size:           fileSize,
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

	err = s.SaveFileMetadata(nodeHash, fHash, fileMetadata)
	if err != nil {
		os.Remove(newPath)
		writeHeaderPayload(w, http.StatusInternalServerError, `{"error": "`+err.Error()+`"}`)
		return
	}

	writeHeaderPayload(w, http.StatusOK, fmt.Sprintf(`{"file_name":"%s","file_hash": "%s", "merkle_root_hash": "%s", "size": %d}`, fileMetadata.FileName, fileMetadata.Hash, fileMetadata.MerkleRootHash, fileMetadata.Size))
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

func validateFileName(fileName string) bool {
	// Clean the file name
	fileName = filepath.Clean(fileName)

	// Define a regular expression pattern for valid file names
	pattern := "^[^<>:\"/\\\\|?*\\x00-\\x1F]+(?: [^<>:\"/\\\\|?*\\x00-\\x1F]+)*$"

	// Compile the regular expression
	regex, err := regexp.Compile(pattern)
	if err != nil {
		// Handle the error
		return false
	}

	// Check if the file name matches the pattern
	return regex.MatchString(fileName)
}
