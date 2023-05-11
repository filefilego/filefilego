package contract

import (
	"bytes"
	"context"
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/filefilego/filefilego/common"
	"github.com/filefilego/filefilego/common/hexutil"
	"github.com/filefilego/filefilego/database"
	"github.com/filefilego/filefilego/node/protocols/messages"
	log "github.com/sirupsen/logrus"
)

const dataPrefix = "contract_data"

// Interface defines the functionalities of contract store.
type Interface interface {
	CreateContract(contract *messages.DownloadContractProto) error
	GetContract(contractHash string) (*messages.DownloadContractProto, error)
	GetContractFileInfo(contractHash string, fileHash []byte) (FileInfo, error)
	SetMerkleTreeNodes(contractHash string, fileHash []byte, merkleTreeNodes [][]byte) error
	SetKeyIVEncryptionTypeRandomizedFileSegments(contractHash string, fileHash []byte, key, iv, merkleRootHash []byte, encryptionType common.EncryptionType, randomizedSegments []int, fileSize uint64) error
	SetProofOfTransferVerified(contractHash string, fileHash []byte, verified bool) error
	SetReceivedUnencryptedDataFromFileHoster(contractHash string, fileHash []byte, transferred bool) error
	DeleteContract(contractHash string) error
	GetContractFiles(contractHash string) ([]FileInfo, error)
	ReleaseContractFees(contractHash string)
	GetReleaseContractFeesStatus(contractHash string) bool
	LoadFromDB() error
	IncrementTransferredBytes(contractHash string, fileHash []byte, fileNamePart, destinationFilePath string, filePartFromRange, filePartToRange int64, count uint64)
	SetFilePartDownloadError(contractHash string, fileHash []byte, fileNamePart, errorMessage string)
	GetTransferredBytes(contractHash string, fileHash []byte) uint64
	SetError(contractHash string, fileHash []byte, errorMessage string)
	SetFileSize(contractHash string, fileHash []byte, fileSize uint64)
	SetFileDecryptionStatus(contractHash string, fileHash []byte, decryptionStatus FileDecryptionStatus)
	GetDownoadedFilePartInfos(contractHash string, fileHash []byte) []BytesTransferStats
	PurgeInactiveContracts(int64) error
	SetContractFileDownloadContexts(key string, ctxData ContextFileDownloadData)
	CancelContractFileDownloadContexts(key string) error
	ResetTransferredBytes(contractHash string, fileHash []byte) error
}

// FileInfo represents a contract with the file information.
type FileInfo struct {
	FileSize                              uint64
	Key                                   []byte
	IV                                    []byte
	MerkleRootHash                        []byte
	FileHash                              []byte
	RandomSegments                        []int
	MerkleTreeNodes                       [][]byte
	EncryptionType                        common.EncryptionType
	ProofOfTransferVerified               bool
	ReceivedUnencryptedDataFromFileHoster bool
	Error                                 string
	FileDecryptionStatus                  FileDecryptionStatus
}

// BytesTransferStats represents the metadata of a transferred data file part.
type BytesTransferStats struct {
	FromByteRange       int64
	ToByteRange         int64
	DestinationFilePath string
	FilePartName        string
	BytesTransfer       uint64
	ErrorMessage        string
}

// ContextFileDownloadData
type ContextFileDownloadData struct {
	From   int64
	To     int64
	Ctx    context.Context
	Cancel context.CancelFunc
}

// Store represents the contract stores.
type Store struct {
	db            database.Database
	fileContracts map[string][]FileInfo
	// contractfileDownloadContxts map key is contractHash + fileHash
	contractfileDownloadContxts map[string][]ContextFileDownloadData
	contractsCreatedAt          map[string]int64
	contracts                   map[string]*messages.DownloadContractProto
	releasedContractFees        map[string]struct{}
	bytesTransferred            map[string]map[string]map[string]BytesTransferStats
	mu                          sync.RWMutex
	muRC                        sync.RWMutex
}

// FileDecryptionStatus represents the file decryption status.
type FileDecryptionStatus string

const (
	FileNotDecrypted    FileDecryptionStatus = ""
	FileDecrypted       FileDecryptionStatus = "decrypted"
	FileDecrypting      FileDecryptionStatus = "decrypting"
	FileDecryptionError FileDecryptionStatus = "decryption_error"
)

type persistedData struct {
	FileContracts        map[string][]FileInfo
	Contracts            map[string]*messages.DownloadContractProto
	ReleasedContractFees map[string]struct{}
	ContractsCreatedAt   map[string]int64
	BytesTransferred     map[string]map[string]map[string]BytesTransferStats
}

// New constructs a contract store.
func New(db database.Database) (*Store, error) {
	if db == nil {
		return nil, errors.New("database is nil")
	}

	store := &Store{
		db:                          db,
		fileContracts:               make(map[string][]FileInfo),
		contractfileDownloadContxts: make(map[string][]ContextFileDownloadData),
		contractsCreatedAt:          make(map[string]int64),
		contracts:                   make(map[string]*messages.DownloadContractProto),
		releasedContractFees:        make(map[string]struct{}),
		bytesTransferred:            make(map[string]map[string]map[string]BytesTransferStats),
	}

	return store, nil
}

// CancelContractFileDownloadContexts cancels all the contexts file part downloads.
func (c *Store) CancelContractFileDownloadContexts(key string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	cfDownloadContexts, ok := c.contractfileDownloadContxts[key]
	if !ok {
		return errors.New("contractFileHash not found")
	}

	for _, v := range cfDownloadContexts {
		v.Cancel()
	}

	delete(c.contractfileDownloadContxts, key)

	return nil
}

// SetContractFileDownloadContexts stores the contexts for downloading file parts.
// these contexts can be canceled in future.
func (c *Store) SetContractFileDownloadContexts(key string, ctxData ContextFileDownloadData) {
	c.mu.Lock()
	defer c.mu.Unlock()

	cfDownloadContexts, ok := c.contractfileDownloadContxts[key]
	if !ok {
		c.contractfileDownloadContxts[key] = []ContextFileDownloadData{ctxData}
		return
	}

	cfDownloadContexts = append(cfDownloadContexts, ctxData)
	c.contractfileDownloadContxts[key] = cfDownloadContexts
}

type contractTime struct {
	contractHash string
	timestamp    int64
}

// PurgeInactiveContracts removes inactive contracts
// Purge after 5 days (60 * 60 * 24 * 5)
func (c *Store) PurgeInactiveContracts(purgeAfterSeconds int64) error {
	now := time.Now().Unix()

	contracts := make([]contractTime, 0)
	for contractHash, timestamp := range c.contractsCreatedAt {
		if now-timestamp > purgeAfterSeconds {
			contracts = append(contracts, contractTime{
				contractHash: contractHash,
				timestamp:    timestamp,
			})
		}
	}

	for _, v := range contracts {
		err := c.DeleteContract(v.contractHash)
		if err != nil {
			log.Warnf("failed to purge contract %s : %s", v.contractHash, err.Error())
		}
	}

	return nil
}

// SetFilePartDownloadError sets an error for a file part download.
func (c *Store) SetFilePartDownloadError(contractHash string, fileHash []byte, fileNamePart, errorMessage string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	fh := hexutil.EncodeNoPrefix(fileHash)
	_, ok := c.bytesTransferred[contractHash]

	if !ok {
		c.bytesTransferred[contractHash] = make(map[string]map[string]BytesTransferStats)
		c.bytesTransferred[contractHash][fh] = map[string]BytesTransferStats{fileNamePart: {
			FilePartName: fileNamePart,
			ErrorMessage: errorMessage,
		}}
		return
	}

	_, ok = c.bytesTransferred[contractHash][fh]
	if !ok {
		c.bytesTransferred[contractHash][fh] = map[string]BytesTransferStats{fileNamePart: {
			FilePartName: fileNamePart,
			ErrorMessage: errorMessage,
		}}
		return
	}

	filePartStats, ok := c.bytesTransferred[contractHash][fh][fileNamePart]
	if !ok {
		c.bytesTransferred[contractHash][fh][fileNamePart] = BytesTransferStats{
			FilePartName: fileNamePart,
			ErrorMessage: errorMessage,
		}
		return
	}

	filePartStats.ErrorMessage = errorMessage
	c.bytesTransferred[contractHash][fh][fileNamePart] = filePartStats
}

// ResetTransferredBytes resets file transfer bytes to zero.
func (c *Store) ResetTransferredBytes(contractHash string, fileHash []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	fh := hexutil.EncodeNoPrefix(fileHash)
	ch, ok := c.bytesTransferred[contractHash]
	if !ok {
		return errors.New("contract was not found")
	}

	delete(ch, fh)
	c.bytesTransferred[contractHash] = ch
	return nil
}

// IncrementTransferredBytes increments the number of bytes transferred for a file.
func (c *Store) IncrementTransferredBytes(contractHash string, fileHash []byte, fileNamePart, destinationFilePath string, filePartFromRange, filePartToRange int64, count uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()

	fh := hexutil.EncodeNoPrefix(fileHash)
	_, ok := c.bytesTransferred[contractHash]

	if !ok {
		c.bytesTransferred[contractHash] = make(map[string]map[string]BytesTransferStats)
		c.bytesTransferred[contractHash][fh] = map[string]BytesTransferStats{fileNamePart: {
			FromByteRange:       filePartFromRange,
			ToByteRange:         filePartToRange,
			FilePartName:        fileNamePart,
			DestinationFilePath: destinationFilePath,
			BytesTransfer:       count,
		}}
		return
	}

	_, ok = c.bytesTransferred[contractHash][fh]
	if !ok {
		c.bytesTransferred[contractHash][fh] = map[string]BytesTransferStats{fileNamePart: {
			FromByteRange:       filePartFromRange,
			ToByteRange:         filePartToRange,
			FilePartName:        fileNamePart,
			DestinationFilePath: destinationFilePath,
			BytesTransfer:       count,
		}}
		return
	}

	filePartStats, ok := c.bytesTransferred[contractHash][fh][fileNamePart]
	if !ok {
		c.bytesTransferred[contractHash][fh][fileNamePart] = BytesTransferStats{
			FromByteRange:       filePartFromRange,
			ToByteRange:         filePartToRange,
			FilePartName:        fileNamePart,
			DestinationFilePath: destinationFilePath,
			BytesTransfer:       count,
		}
		return
	}

	filePartStats.FromByteRange += filePartFromRange
	filePartStats.BytesTransfer += count

	c.bytesTransferred[contractHash][fh][fileNamePart] = filePartStats
}

// GetDownoadedFilePartInfos gets the downloaded file part infos.
func (c *Store) GetDownoadedFilePartInfos(contractHash string, fileHash []byte) []BytesTransferStats {
	c.mu.RLock()
	defer c.mu.RUnlock()

	fh := hexutil.EncodeNoPrefix(fileHash)

	d := c.bytesTransferred[contractHash][fh]

	allFiles := make([]BytesTransferStats, 0)

	for _, v := range d {
		allFiles = append(allFiles, v)
	}
	sort.Slice(allFiles, func(i, j int) bool { return allFiles[i].ToByteRange < allFiles[j].ToByteRange })

	return allFiles
}

// GetTransferredBytes gets the transferred bytes for a file.
func (c *Store) GetTransferredBytes(contractHash string, fileHash []byte) uint64 {
	c.mu.RLock()
	defer c.mu.RUnlock()

	fh := hexutil.EncodeNoPrefix(fileHash)

	d := c.bytesTransferred[contractHash][fh]

	total := uint64(0)
	for _, v := range d {
		total += v.BytesTransfer
	}

	return total
}

// ReleaseContractFees stores an inmem indication that contract fees were released to file hoster.
func (c *Store) ReleaseContractFees(contractHash string) {
	c.muRC.Lock()
	defer c.muRC.Unlock()

	c.releasedContractFees[contractHash] = struct{}{}
}

// GetReleaseContractFeesStatus returns true if contract fees were released.
func (c *Store) GetReleaseContractFeesStatus(contractHash string) bool {
	c.muRC.RLock()
	defer c.muRC.RUnlock()

	_, ok := c.releasedContractFees[contractHash]
	return ok
}

// DeleteContract removes a contract.
func (c *Store) DeleteContract(contractHash string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	_, ok := c.contracts[contractHash]
	if !ok {
		return fmt.Errorf("contract %s hash not found", contractHash)
	}

	delete(c.contracts, contractHash)
	delete(c.fileContracts, contractHash)
	delete(c.bytesTransferred, contractHash)
	delete(c.releasedContractFees, contractHash)
	delete(c.contractsCreatedAt, contractHash)

	_ = c.persistToDB()

	return nil
}

// CreateContract creates a contract with the zero values for file information
func (c *Store) CreateContract(contract *messages.DownloadContractProto) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	contractHash := hexutil.Encode(contract.ContractHash)
	_, ok := c.contracts[contractHash]
	if ok {
		return fmt.Errorf("contract already exists with %s hash", contractHash)
	}

	// use local unix time
	c.contractsCreatedAt[contractHash] = time.Now().Unix()
	c.contracts[contractHash] = contract
	c.fileContracts[contractHash] = make([]FileInfo, 0)

	_ = c.persistToDB()

	return nil
}

// GetContract get a contract.
func (c *Store) GetContract(contractHash string) (*messages.DownloadContractProto, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	contract, ok := c.contracts[contractHash]
	if !ok {
		return nil, fmt.Errorf("contract %s not found", contractHash)
	}

	return contract, nil
}

// GetContractFileInfo returns the file info given a contract hash and file hash
func (c *Store) GetContractFileInfo(contractHash string, fileHash []byte) (FileInfo, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	fileContracts, ok := c.fileContracts[contractHash]
	if !ok {
		return FileInfo{}, errors.New("contract not found")
	}

	for _, v := range fileContracts {
		if bytes.Equal(v.FileHash, fileHash) {
			return v, nil
		}
	}

	return FileInfo{}, errors.New("file hash not found")
}

// GetContractFiles returns the files info given a contract hash
func (c *Store) GetContractFiles(contractHash string) ([]FileInfo, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	fileContracts, ok := c.fileContracts[contractHash]
	if !ok {
		return nil, errors.New("contract not found")
	}

	filesInfos := make([]FileInfo, len(fileContracts))
	copy(filesInfos, fileContracts)

	return filesInfos, nil
}

// SetFileDecryptionStatus sets a file encryption status.
func (c *Store) SetFileDecryptionStatus(contractHash string, fileHash []byte, decryptionStatus FileDecryptionStatus) {
	c.mu.Lock()
	defer c.mu.Unlock()

	fileContracts, ok := c.fileContracts[contractHash]
	if !ok {
		return
	}

	foundFileContractIndex := -1
	for idx, v := range fileContracts {
		if bytes.Equal(v.FileHash, fileHash) {
			foundFileContractIndex = idx
		}
	}

	// if file info item isn't there create it
	if foundFileContractIndex == -1 {
		fileInfo := FileInfo{
			FileHash:             make([]byte, len(fileHash)),
			FileDecryptionStatus: decryptionStatus,
		}
		copy(fileInfo.FileHash, fileHash)

		fileInfoSlice := c.fileContracts[contractHash]
		fileInfoSlice = append(fileInfoSlice, fileInfo)
		c.fileContracts[contractHash] = fileInfoSlice
		return
	}

	v := c.fileContracts[contractHash][foundFileContractIndex]
	v.FileDecryptionStatus = decryptionStatus
	c.fileContracts[contractHash][foundFileContractIndex] = v

	_ = c.persistToDB()
}

// SetError sets an error indication for a filehash
func (c *Store) SetError(contractHash string, fileHash []byte, errorMessage string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	fileContracts, ok := c.fileContracts[contractHash]
	if !ok {
		return
	}

	foundFileContractIndex := -1
	for idx, v := range fileContracts {
		if bytes.Equal(v.FileHash, fileHash) {
			foundFileContractIndex = idx
		}
	}

	// if file info item isn't there create it
	if foundFileContractIndex == -1 {
		fileInfo := FileInfo{
			FileHash: make([]byte, len(fileHash)),
			Error:    errorMessage,
		}
		copy(fileInfo.FileHash, fileHash)

		fileInfoSlice := c.fileContracts[contractHash]
		fileInfoSlice = append(fileInfoSlice, fileInfo)
		c.fileContracts[contractHash] = fileInfoSlice
		return
	}

	v := c.fileContracts[contractHash][foundFileContractIndex]
	v.Error = errorMessage
	c.fileContracts[contractHash][foundFileContractIndex] = v

	_ = c.persistToDB()
}

// SetFileSize sets a file size
func (c *Store) SetFileSize(contractHash string, fileHash []byte, fileSize uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()

	fileContracts, ok := c.fileContracts[contractHash]
	if !ok {
		return
	}

	foundFileContractIndex := -1
	for idx, v := range fileContracts {
		if bytes.Equal(v.FileHash, fileHash) {
			foundFileContractIndex = idx
		}
	}

	// if file info item isn't there create it
	if foundFileContractIndex == -1 {
		fileInfo := FileInfo{
			FileHash: make([]byte, len(fileHash)),
			FileSize: fileSize,
		}
		copy(fileInfo.FileHash, fileHash)

		fileInfoSlice := c.fileContracts[contractHash]
		fileInfoSlice = append(fileInfoSlice, fileInfo)
		c.fileContracts[contractHash] = fileInfoSlice
		return
	}

	v := c.fileContracts[contractHash][foundFileContractIndex]
	v.FileSize = fileSize
	c.fileContracts[contractHash][foundFileContractIndex] = v

	_ = c.persistToDB()
}

// SetMerkleTreeNodes sets a merkle tree nodes of the file.
func (c *Store) SetMerkleTreeNodes(contractHash string, fileHash []byte, merkleTreeNodes [][]byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	fileContracts, ok := c.fileContracts[contractHash]
	if !ok {
		return errors.New("contract not found")
	}

	foundFileContractIndex := -1
	for idx, v := range fileContracts {
		if bytes.Equal(v.FileHash, fileHash) {
			foundFileContractIndex = idx
		}
	}

	// if file info item isn't there create it
	if foundFileContractIndex == -1 {
		fileInfo := FileInfo{
			FileHash:        make([]byte, len(fileHash)),
			MerkleTreeNodes: make([][]byte, len(merkleTreeNodes)),
		}
		copy(fileInfo.FileHash, fileHash)

		for i := 0; i < len(merkleTreeNodes); i++ {
			fileInfo.MerkleTreeNodes[i] = make([]byte, len(merkleTreeNodes[i]))
			copy(fileInfo.MerkleTreeNodes[i], merkleTreeNodes[i])
		}

		fileInfoSlice := c.fileContracts[contractHash]
		fileInfoSlice = append(fileInfoSlice, fileInfo)
		c.fileContracts[contractHash] = fileInfoSlice
		return nil
	}

	v := c.fileContracts[contractHash][foundFileContractIndex]
	v.MerkleTreeNodes = make([][]byte, len(merkleTreeNodes))
	for i := 0; i < len(merkleTreeNodes); i++ {
		v.MerkleTreeNodes[i] = make([]byte, len(merkleTreeNodes[i]))
		copy(v.MerkleTreeNodes[i], merkleTreeNodes[i])
	}
	c.fileContracts[contractHash][foundFileContractIndex] = v

	_ = c.persistToDB()

	return nil
}

// SetKeyIVEncryptionTypeRandomizedFileSegments sets the key and iv, encryption type and randomized segments of the of file.
func (c *Store) SetKeyIVEncryptionTypeRandomizedFileSegments(contractHash string, fileHash []byte, key, iv, merkleRootHash []byte, encryptionType common.EncryptionType, randomizedSegments []int, fileSize uint64) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	fileContracts, ok := c.fileContracts[contractHash]
	if !ok {
		return errors.New("contract not found")
	}

	foundFileContractIndex := -1
	for idx, v := range fileContracts {
		if bytes.Equal(v.FileHash, fileHash) {
			foundFileContractIndex = idx
		}
	}

	if foundFileContractIndex == -1 {
		fileInfo := FileInfo{
			FileSize:       fileSize,
			FileHash:       make([]byte, len(fileHash)),
			Key:            make([]byte, len(key)),
			IV:             make([]byte, len(iv)),
			MerkleRootHash: make([]byte, len(merkleRootHash)),
			RandomSegments: make([]int, len(randomizedSegments)),
			EncryptionType: encryptionType,
		}
		copy(fileInfo.FileHash, fileHash)
		copy(fileInfo.Key, key)
		copy(fileInfo.IV, iv)
		copy(fileInfo.MerkleRootHash, merkleRootHash)
		copy(fileInfo.RandomSegments, randomizedSegments)

		fileInfoSlice := c.fileContracts[contractHash]
		fileInfoSlice = append(fileInfoSlice, fileInfo)
		c.fileContracts[contractHash] = fileInfoSlice
		_ = c.persistToDB()
		return nil
	}

	v := c.fileContracts[contractHash][foundFileContractIndex]

	if len(v.Key) > 0 {
		return errors.New("encryption data is already set")
	}

	v.Key = make([]byte, len(key))
	copy(v.Key, key)

	v.IV = make([]byte, len(iv))
	copy(v.IV, iv)

	v.MerkleRootHash = make([]byte, len(merkleRootHash))
	copy(v.MerkleRootHash, merkleRootHash)

	v.RandomSegments = make([]int, len(randomizedSegments))
	copy(v.RandomSegments, randomizedSegments)

	v.EncryptionType = encryptionType
	v.FileSize = fileSize

	c.fileContracts[contractHash][foundFileContractIndex] = v
	_ = c.persistToDB()

	return nil
}

// SetProofOfTransferVerified sets if a proof of transfer was successful.
func (c *Store) SetProofOfTransferVerified(contractHash string, fileHash []byte, verified bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	fileContracts, ok := c.fileContracts[contractHash]
	if !ok {
		return errors.New("contract not found")
	}

	for idx, v := range fileContracts {
		if bytes.Equal(v.FileHash, fileHash) {
			v.ProofOfTransferVerified = verified
			c.fileContracts[contractHash][idx] = v
			return nil
		}
	}

	_ = c.persistToDB()

	return errors.New("file hash not found")
}

// SetReceivedUnencryptedDataFromFileHoster if all unencrypted data were transferred from file hoster to verifier node.
func (c *Store) SetReceivedUnencryptedDataFromFileHoster(contractHash string, fileHash []byte, transferred bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	fileContracts, ok := c.fileContracts[contractHash]
	if !ok {
		return errors.New("contract not found")
	}

	for idx, v := range fileContracts {
		if bytes.Equal(v.FileHash, fileHash) {
			v.ReceivedUnencryptedDataFromFileHoster = transferred
			c.fileContracts[contractHash][idx] = v
			return nil
		}
	}

	_ = c.persistToDB()

	return errors.New("file hash not found")
}

func (c *Store) persistToDB() error {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	data := persistedData{
		FileContracts:        c.fileContracts,
		ContractsCreatedAt:   c.contractsCreatedAt,
		Contracts:            c.contracts,
		ReleasedContractFees: c.releasedContractFees,
		BytesTransferred:     c.bytesTransferred,
	}
	err := enc.Encode(data)
	if err != nil {
		return fmt.Errorf("failed to encode gob data: %w", err)
	}

	err = c.db.Put([]byte(dataPrefix), buf.Bytes())
	if err != nil {
		return fmt.Errorf("failed to persist data to db: %w", err)
	}

	return nil
}

// LoadFromDB loads the persisted data into memory.
func (c *Store) LoadFromDB() error {
	data, err := c.db.Get([]byte(dataPrefix))
	if err != nil {
		return fmt.Errorf("failed to load from database: %w", err)
	}
	var buf bytes.Buffer
	n, err := buf.Write(data)
	if err != nil {
		return fmt.Errorf("failed to write to buffer of gob decoder: %w", err)
	}

	if n != len(data) {
		return errors.New("length of data written to the gob buffer don't match the loaded database content")
	}

	dec := gob.NewDecoder(&buf)
	var pd persistedData
	err = dec.Decode(&pd)
	if err != nil {
		return fmt.Errorf("failed to decode gob data: %w", err)
	}

	c.contracts = pd.Contracts
	c.contractsCreatedAt = pd.ContractsCreatedAt
	c.fileContracts = pd.FileContracts
	c.releasedContractFees = pd.ReleasedContractFees
	c.bytesTransferred = pd.BytesTransferred

	return nil
}

type contractFiles struct {
	Hash      string
	Message   *messages.DownloadContractProto
	FileInfos []FileInfo
}

// Debug serves the internal state
func (c *Store) Debug(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
	w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")

	if r.Method == "OPTIONS" {
		return
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	allContracts := make([]contractFiles, 0)

	for contractHash, v := range c.contracts {
		ctrct := contractFiles{
			Hash:    contractHash,
			Message: v,
		}
		fileInfos, err := c.GetContractFiles(contractHash)
		if err == nil {
			ctrct.FileInfos = make([]FileInfo, len(fileInfos))
			copy(ctrct.FileInfos, fileInfos)
		}
		allContracts = append(allContracts, ctrct)
	}

	log.Info("marshaling all contracts")

	j, err := json.Marshal(allContracts)
	if err != nil {
		writeHeaderPayload(w, http.StatusOK, ``)
		return
	}

	writeHeaderPayload(w, http.StatusOK, string(j))
}

func writeHeaderPayload(w http.ResponseWriter, status int, payload string) {
	w.WriteHeader(status)
	// nolint:errcheck
	w.Write([]byte(payload))
}
