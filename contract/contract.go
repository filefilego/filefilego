package contract

import (
	"bytes"
	"encoding/gob"
	"errors"
	"fmt"
	"sync"

	"github.com/filefilego/filefilego/common"
	"github.com/filefilego/filefilego/common/hexutil"
	"github.com/filefilego/filefilego/database"
	"github.com/filefilego/filefilego/node/protocols/messages"
)

// TODO: purge if old using a time window of x days

const dataPrefix = "contract_data"

// Interface defines the functionalities of contract store.
type Interface interface {
	CreateContract(contract *messages.DownloadContractProto) error
	GetContract(contractHash string) (*messages.DownloadContractProto, error)
	GetContractFileInfo(contractHash string, fileHash []byte) (FileInfo, error)
	SetMerkleTreeNodes(contractHash string, fileHash []byte, merkleTreeNodes [][]byte) error
	SetKeyIVEncryptionTypeRandomizedFileSegments(contractHash string, fileHash []byte, key, iv, merkleRootHash []byte, encryptionType common.EncryptionType, randomizedSegments []int, fileSize uint64) error
	SetProofOfTransferVerified(contractHash string, fileHash []byte, verified bool) error
	SetReceivedUnencryptedDataFromFileHoster(contractHash string, fileHash []byte, transfered bool) error
	DeleteContract(contractHash string) error
	GetContractFiles(contractHash string) ([]FileInfo, error)
	ReleaseContractFees(contractHash string)
	GetReleaseContractFeesStatus(contractHash string) bool
	LoadFromDB() error
	IncrementTransferedBytes(contractHash string, fileHash []byte, count uint64)
	GetTransferedBytes(contractHash string, fileHash []byte) uint64
	SetError(contractHash string, fileHash []byte, errorMessage string)
	SetFileSize(contractHash string, fileHash []byte, fileSize uint64)
	SetFileDecrypted(contractHash string, fileHash []byte, decrypted bool)
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
	FileDecrypted                         bool
}

// Store represents the contract stores.
type Store struct {
	db                   database.Database
	fileContracts        map[string][]FileInfo
	contracts            map[string]*messages.DownloadContractProto
	releasedContractFees map[string]struct{}
	bytesTransfered      map[string]map[string]uint64
	mu                   sync.RWMutex
	muRC                 sync.RWMutex
}

type persistedData struct {
	FileContracts        map[string][]FileInfo
	Contracts            map[string]*messages.DownloadContractProto
	ReleasedContractFees map[string]struct{}
}

// New constructs a contract store.
func New(db database.Database) (*Store, error) {
	if db == nil {
		return nil, errors.New("database is nil")
	}

	store := &Store{
		db:                   db,
		fileContracts:        make(map[string][]FileInfo),
		contracts:            make(map[string]*messages.DownloadContractProto),
		releasedContractFees: make(map[string]struct{}),
		bytesTransfered:      make(map[string]map[string]uint64),
	}

	return store, nil
}

// IncrementTransferedBytes increments the number of bytes transfered for a file.
func (c *Store) IncrementTransferedBytes(contractHash string, fileHash []byte, count uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()

	fh := hexutil.EncodeNoPrefix(fileHash)
	_, ok := c.bytesTransfered[contractHash]

	if !ok {
		c.bytesTransfered[contractHash] = make(map[string]uint64)
		c.bytesTransfered[contractHash][fh] = count
		return
	}

	bytesStats, ok := c.bytesTransfered[contractHash][fh]
	if !ok {
		c.bytesTransfered[contractHash][fh] = count
		return
	}

	bytesStats += count
	c.bytesTransfered[contractHash][fh] = bytesStats
}

// GetTransferedBytes gets the transfered bytes for a file.
func (c *Store) GetTransferedBytes(contractHash string, fileHash []byte) uint64 {
	c.mu.RLock()
	defer c.mu.RUnlock()

	fh := hexutil.EncodeNoPrefix(fileHash)

	d := c.bytesTransfered[contractHash][fh]
	return d
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
	delete(c.bytesTransfered, contractHash)
	delete(c.releasedContractFees, contractHash)

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

// SetFileDecrypted sets true if a file was decrypted.
func (c *Store) SetFileDecrypted(contractHash string, fileHash []byte, decrypted bool) {
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
			FileHash:      make([]byte, len(fileHash)),
			FileDecrypted: decrypted,
		}
		copy(fileInfo.FileHash, fileHash)

		fileInfoSlice := c.fileContracts[contractHash]
		fileInfoSlice = append(fileInfoSlice, fileInfo)
		c.fileContracts[contractHash] = fileInfoSlice
		return
	}

	v := c.fileContracts[contractHash][foundFileContractIndex]
	v.FileDecrypted = decrypted
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
		return nil
	}

	v := c.fileContracts[contractHash][foundFileContractIndex]
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

// SetProofOfTransferVerified sets if a proof of transfer was successfull.
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

// SetReceivedUnencryptedDataFromFileHoster if all unencrypted data were transfered from file hoster to verifier node.
func (c *Store) SetReceivedUnencryptedDataFromFileHoster(contractHash string, fileHash []byte, transfered bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	fileContracts, ok := c.fileContracts[contractHash]
	if !ok {
		return errors.New("contract not found")
	}

	for idx, v := range fileContracts {
		if bytes.Equal(v.FileHash, fileHash) {
			v.ReceivedUnencryptedDataFromFileHoster = transfered
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
		Contracts:            c.contracts,
		ReleasedContractFees: c.releasedContractFees,
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
	c.fileContracts = pd.FileContracts
	c.releasedContractFees = pd.ReleasedContractFees

	return nil
}
