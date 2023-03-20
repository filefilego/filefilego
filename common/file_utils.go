package common

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	mrand "math/rand"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"sort"

	"github.com/cbergoon/merkletree"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/chacha20"
)

// EncryptionType represents an encryption mechanism.
type EncryptionType int32

const (
	// EncryptionTypeAES key and iv are both 32 bytes for aes
	EncryptionTypeAES256 EncryptionType = 1
	// EncryptionTypeChacha20 key 32 bytes, iv(nounce) 32 bytes
	EncryptionTypeChacha20 EncryptionType = 2

	// KB represents 1024 bytes
	KB = 1024

	// MB represents 1024 KBytes
	MB = 1024 * 1024

	// 8KB
	bufferSize = 8192
)

// DataEncryptor is an interface to define the functionality of a data encryptor.
type DataEncryptor interface {
	StreamEncryptor() (cipher.Stream, error)
	EncryptionType() EncryptionType
}

// FileBlockRange represents range of bytes to be encrypted.
type FileBlockRange struct {
	mustEncrypt bool
	from        int
	to          int
}

// FileBlockHash represents a hash of a block (range of bytes) of a file.
type FileBlockHash struct {
	X []byte
}

// CalculateHash hashes the content of FileBlockHash.x.
func (f FileBlockHash) CalculateHash() ([]byte, error) {
	h := sha256.New()
	if _, err := h.Write(f.X); err != nil {
		return nil, err
	}

	return h.Sum(nil), nil
}

// Equals tests for equality of two FileBlockHash.
func (f FileBlockHash) Equals(other merkletree.Content) (bool, error) {
	return bytes.Equal(f.X, other.(FileBlockHash).X), nil
}

// Encryptor represents an encryptor.
type Encryptor struct {
	encryptionType EncryptionType
	key            []byte
	iv             []byte
}

// EncryptionType returns the type of the encryptor.
func (e *Encryptor) EncryptionType() EncryptionType {
	return e.encryptionType
}

// StreamEncryptor gets the encryptor.
func (e *Encryptor) StreamEncryptor() (cipher.Stream, error) {
	if e.encryptionType == EncryptionTypeAES256 {
		block, err := aes.NewCipher(e.key)
		if err != nil {
			return nil, fmt.Errorf("failed to create AES256 cipher: %w", err)
		}

		if len(e.iv) != block.BlockSize() {
			return nil, fmt.Errorf("iv length %d is not equal to blocksize %d of AES256", len(e.iv), block.BlockSize())
		}
		return cipher.NewCTR(block, e.iv), nil
	} else if e.encryptionType == EncryptionTypeChacha20 {
		stream, err := chacha20.NewUnauthenticatedCipher(e.key, e.iv)
		if err != nil {
			return nil, fmt.Errorf("failed to create chacha20 cipher: %w", err)
		}
		return stream, nil
	}

	return nil, errors.New("unsupported encryptor")
}

// NewEncryptor is a new encryptor.
func NewEncryptor(encryptionType EncryptionType, key, iv []byte) (*Encryptor, error) {
	switch encryptionType {
	case EncryptionTypeChacha20:
		{
			if len(key) != 32 {
				return nil, errors.New("chacha20 key length is not 32 bytes")
			}

			if len(iv) != 24 {
				return nil, errors.New("chacha20 iv length is not 24 bytes")
			}
		}
	case EncryptionTypeAES256:
		{
			if len(key) != 32 {
				return nil, errors.New("AES256 key length is not 32 bytes")
			}

			if len(iv) != 16 {
				return nil, errors.New("AES256 iv length is not 32 bytes")
			}
		}
	default:
		return nil, errors.New("unsupported encryption type")
	}

	encryptor := &Encryptor{
		encryptionType: encryptionType,
		key:            make([]byte, len(key)),
		iv:             make([]byte, len(iv)),
	}

	copy(encryptor.key, key)
	copy(encryptor.iv, iv)

	return encryptor, nil
}

// ReadWriteSeekerSyncer is used to add Sync to ReadWriteSeeker interface.
type ReadWriteSeekerSyncer interface {
	io.ReadWriteSeeker
	Sync() error
}

// DecryptFileSegments decrypts the segments and replaces them in the original file and then performs a file block/segment re-arrangement and writes to the output.
func DecryptFileSegments(fileSize, totalSegments, percentageToEncryptData int, randomizedFileSegments []int, input ReadWriteSeekerSyncer, output io.WriteCloser, encryptor DataEncryptor, onlyFileReArrangement bool) error {
	howManySegments, segmentSizeBytes, totalSegmentsToEncrypt, encryptEverySegment := FileSegmentsInfo(fileSize, totalSegments, percentageToEncryptData)
	ranges, ok := PrepareFileBlockRanges(0, howManySegments-1, fileSize, howManySegments, segmentSizeBytes, totalSegmentsToEncrypt, encryptEverySegment, randomizedFileSegments)
	if !ok || len(ranges) == 0 {
		return errors.New("failed to prepare file blocks")
	}

	for i, v := range ranges {
		if v.mustEncrypt {
			from := i * segmentSizeBytes
			to := from + segmentSizeBytes - 1
			diff := (to - from) + 1
			totalOffset := 0
			stream, err := encryptor.StreamEncryptor()
			if err != nil {
				return fmt.Errorf("failed to create a decryptor: %w", err)
			}
			for diff > 0 {
				totalBytesRead := 0
				if diff > bufferSize {
					diff -= bufferSize
					totalBytesRead = bufferSize
				} else {
					totalBytesRead = diff
					diff -= diff
				}

				buf := make([]byte, totalBytesRead)
				_, err := input.Seek(int64(from+totalOffset), 0)
				if err != nil {
					return fmt.Errorf("failed to seek input file: %w", err)
				}
				n, err := input.Read(buf)
				// this seek is required again to go back to the address we read from in the previous step
				_, seekErr := input.Seek(int64(from+totalOffset), 0)
				if seekErr != nil {
					return fmt.Errorf("failed to seek input file to the point before read: %w", err)
				}
				if n > 0 {
					if !onlyFileReArrangement {
						stream.XORKeyStream(buf, buf[:n])
					}
					totalOffset += n
					okn, err := input.Write(buf[:n])
					if err != nil {
						return fmt.Errorf("failed to replace decrypted bytes from buffer to input file: %w", err)
					}

					if okn != n {
						return errors.New("number of bytes replaced from buffer to input file are not equal")
					}
				}

				if err != nil {
					return fmt.Errorf("failed to read from input file to buffer: %w", err)
				}
			}

			err = input.Sync()
			if err != nil {
				return fmt.Errorf("failed to perform sync on input file: %w", err)
			}
		}
	}

	_, err := input.Seek(0, 0)
	if err != nil {
		return fmt.Errorf("failed to seek to the begining of the file: %w", err)
	}

	for i := 0; i < howManySegments; i++ {
		idx := -1
		for j, v := range randomizedFileSegments {
			if v == i {
				idx = j
				break
			}
		}

		from := idx * segmentSizeBytes
		to := from + segmentSizeBytes - 1

		_, err := input.Seek(int64(from), 0)
		if err != nil {
			return fmt.Errorf("failed to seek to the from index of file block/segment: %w", err)
		}
		diff := (to - from) + 1
		for diff > 0 {
			totalBytesRead := 0
			if diff > bufferSize {
				diff -= bufferSize
				totalBytesRead = bufferSize
			} else {
				totalBytesRead = diff
				diff -= diff
			}

			buf := make([]byte, totalBytesRead)
			n, err := input.Read(buf)
			if n > 0 {
				okn, err := output.Write(buf[:n])
				if okn != n {
					return fmt.Errorf("number of bytes from buffer are different than written to output file: %w", err)
				}
				if err != nil {
					return fmt.Errorf("failed to write buffer to output file: %w", err)
				}
			}

			if err == io.EOF {
				log.Warn("io.EOF")
				continue
			}

			if err != nil {
				return fmt.Errorf("failed to read from decrypted file: %w", err)
			}
		}
	}

	return nil
}

// WriteUnencryptedSegments takes the file segments that need to be encrypted and copies them to output before encryption is performed.
func WriteUnencryptedSegments(fileSize, totalSegments, percentageToEncryptData int, randomizedFileSegments []int, input io.ReadSeekCloser, output io.WriteCloser) error {
	howManySegments, segmentSizeBytes, totalSegmentsToEncrypt, encryptEverySegment := FileSegmentsInfo(fileSize, totalSegments, percentageToEncryptData)
	if len(randomizedFileSegments) != howManySegments {
		return fmt.Errorf("number of final segments %d is not equal to the randomized file segments list %d", howManySegments, len(randomizedFileSegments))
	}

	ranges, ok := PrepareFileBlockRanges(0, howManySegments-1, fileSize, howManySegments, segmentSizeBytes, totalSegmentsToEncrypt, encryptEverySegment, randomizedFileSegments)
	if !ok || len(ranges) == 0 {
		return errors.New("failed to prepare file blocks")
	}

	for i := 0; i < howManySegments; i++ {
		if encryptEverySegment != 0 && i%encryptEverySegment == 0 && totalSegmentsToEncrypt > 0 {
			totalSegmentsToEncrypt--
			from := i * segmentSizeBytes
			to := from + segmentSizeBytes - 1

			_, err := input.Seek(int64(from), 0)
			if err != nil {
				return fmt.Errorf("failed to seek input file at offset %d filesize %d: %w", from, fileSize, err)
			}

			diff := (to - from) + 1

			for diff > 0 {
				totalBytesRead := 0
				if diff > bufferSize {
					diff -= bufferSize
					totalBytesRead = bufferSize
				} else {
					totalBytesRead = diff
					diff -= diff
				}

				buf := make([]byte, totalBytesRead)
				n, err := input.Read(buf)
				if n > 0 {
					okn, err := output.Write(buf[:n])
					if okn != n {
						return errors.New("number of bytes written from buffer to output are not equal")
					}

					if err != nil {
						return fmt.Errorf("failed to write to output: %w", err)
					}
				}

				if err == io.EOF {
					log.Warn("io.EOF when encrypting")
					break
				}

				if err != nil {
					return fmt.Errorf("failed to read from input: %w", err)
				}
			}
		}
	}

	return nil
}

// EncryptAndHashSegments encrypts a file's raw segment given a key and hashes the segment.
func EncryptAndHashSegments(fileSize, totalSegments int, randomizedFileSegments []int, input io.ReadSeekCloser, encryptor DataEncryptor) ([]FileBlockHash, error) {
	howManySegments, segmentSizeBytes, totalSegmentsToEncrypt, encryptEverySegment := FileSegmentsInfo(fileSize, totalSegments, 100)
	if len(randomizedFileSegments) != howManySegments {
		return nil, fmt.Errorf("number of final segments %d is not equal to the randomized file segments list %d", howManySegments, len(randomizedFileSegments))
	}
	ranges, ok := PrepareFileBlockRanges(0, howManySegments-1, fileSize, howManySegments, segmentSizeBytes, totalSegmentsToEncrypt, encryptEverySegment, randomizedFileSegments)
	if !ok || len(ranges) == 0 {
		return nil, errors.New("failed to prepare file blocks")
	}
	sha256Sum := sha256.New()
	hashes := make([]FileBlockHash, 0)

	for _, v := range ranges {
		sha256Sum.Reset()
		stream, err := encryptor.StreamEncryptor()
		if err != nil {
			return nil, fmt.Errorf("failed to create an encryptor: %w", err)
		}

		_, err = input.Seek(int64(v.from), 0)
		if err != nil {
			return nil, fmt.Errorf("failed to seek input file at offset %d filesize %d: %w", v.from, fileSize, err)
		}

		diff := (v.to - v.from) + 1

		for diff > 0 {
			totalBytesRead := 0
			if diff > bufferSize {
				diff -= bufferSize
				totalBytesRead = bufferSize
			} else {
				totalBytesRead = diff
				diff -= diff
			}

			buf := make([]byte, totalBytesRead)
			n, err := input.Read(buf)
			if n > 0 {
				stream.XORKeyStream(buf, buf[:n])
				okn, err := sha256Sum.Write(buf[:n])
				if okn != n {
					return nil, errors.New("number of bytes written from buffer to sha sum are not equal")
				}

				if err != nil {
					return nil, fmt.Errorf("failed to write to sha sum: %w", err)
				}
			}

			if err == io.EOF {
				log.Warn("io.EOF when encrypting")
				break
			}

			if err != nil {
				return nil, fmt.Errorf("failed to read from input: %w", err)
			}
		}

		hash := sha256Sum.Sum(nil)
		fbh := FileBlockHash{X: make([]byte, len(hash))}
		copy(fbh.X, hash)

		hashes = append(hashes, fbh)
	}

	return hashes, nil
}

// EncryptWriteOutput uses the stream cipher to encrypt the input reader and write to the output.
func EncryptWriteOutput(fileSize, totalSegments, percentageToEncryptData int, randomizedFileSegments []int, input io.ReadSeekCloser, output io.WriteCloser, encryptor DataEncryptor) error {
	howManySegments, segmentSizeBytes, totalSegmentsToEncrypt, encryptEverySegment := FileSegmentsInfo(fileSize, totalSegments, percentageToEncryptData)
	if len(randomizedFileSegments) != howManySegments {
		return fmt.Errorf("number of final segments %d is not equal to the randomized file segments list %d", howManySegments, len(randomizedFileSegments))
	}
	ranges, ok := PrepareFileBlockRanges(0, howManySegments-1, fileSize, howManySegments, segmentSizeBytes, totalSegmentsToEncrypt, encryptEverySegment, randomizedFileSegments)
	if !ok || len(ranges) == 0 {
		return errors.New("failed to prepare file blocks")
	}

	for _, v := range ranges {
		stream, err := encryptor.StreamEncryptor()
		if err != nil {
			return fmt.Errorf("failed to create an encryptor: %w", err)
		}

		_, err = input.Seek(int64(v.from), 0)
		if err != nil {
			return fmt.Errorf("failed to seek input file at offset %d filesize %d: %w", v.from, fileSize, err)
		}

		diff := (v.to - v.from) + 1

		for diff > 0 {
			totalBytesRead := 0
			if diff > bufferSize {
				diff -= bufferSize
				totalBytesRead = bufferSize
			} else {
				totalBytesRead = diff
				diff -= diff
			}

			buf := make([]byte, totalBytesRead)
			n, err := input.Read(buf)
			if n > 0 {
				if v.mustEncrypt {
					stream.XORKeyStream(buf, buf[:n])
				}
				okn, err := output.Write(buf[:n])
				if okn != n {
					return errors.New("number of bytes written from buffer to output are not equal")
				}

				if err != nil {
					return fmt.Errorf("failed to write to output: %w", err)
				}
			}

			if err == io.EOF {
				log.Warn("io.EOF when encrypting")
				break
			}

			if err != nil {
				return fmt.Errorf("failed to read from input: %w", err)
			}
		}
	}

	return nil
}

// PrepareFileBlockRanges returns a list of file block/segments and the order for each block.
// random slice is used to shuffle the byte blocks/segments.
func PrepareFileBlockRanges(from, to, fileSize, totalSegments, segmentSizeBytes, totalSegmentsToEncrypt, encryptEverySegment int, randomSlice []int) ([]FileBlockRange, bool) {
	if fileSize == 0 {
		return nil, false
	}

	if from > to || to > totalSegments-1 {
		return nil, false
	}

	fileRanges := make([]FileBlockRange, 0)

	for i := from; i <= to; i++ {
		start := randomSlice[i] * segmentSizeBytes
		end := start + segmentSizeBytes - 1

		if end > fileSize-1 {
			end = fileSize - 1
		}

		fileRanges = append(fileRanges, FileBlockRange{
			from: start,
			to:   end,
		})
	}

	// make a copy of the randomized ranges
	// and sort them by "from" so we incrementally indicate which segments should be encrypted
	// this way we can derive the correct order from the diff file which is sent for verification using merkle trees
	fileRangesTmp := make([]FileBlockRange, len(fileRanges))
	copy(fileRangesTmp, fileRanges)

	sort.Slice(fileRangesTmp, func(i, j int) bool { return fileRangesTmp[i].from < fileRangesTmp[j].from })

	for i, v := range fileRangesTmp {
		div := v.from / segmentSizeBytes
		if totalSegmentsToEncrypt != 0 && div%encryptEverySegment == 0 {
			totalSegmentsToEncrypt--
			fileRangesTmp[i].mustEncrypt = true
		}
	}

	for _, v := range fileRangesTmp {
		if v.mustEncrypt {
			for idx, j := range fileRanges {
				if v.from == j.from {
					fileRanges[idx].mustEncrypt = true
				}
			}
		}
	}

	return fileRanges, true
}

// RetrieveMerkleTreeNodes retrives the original order of merkle tree given the random list.
func RetrieveMerkleTreeNodesFromFileWithRawData(encryptEverySegment int, randomizedFileSegments []int, merkleTreeItems, merkleTreeOfRawSegments []FileBlockHash) ([]FileBlockHash, error) {
	items := make([]FileBlockHash, 0)
	for i := 0; i < len(randomizedFileSegments); i++ {
		idx := -1
		for j, v := range randomizedFileSegments {
			if v == i {
				idx = j
				break
			}
		}

		if idx == -1 {
			return nil, errors.New("index of randomized file segments not found")
		}

		if idx >= len(merkleTreeItems) {
			return nil, errors.New("index of randomized file segment is greater than the supplied merkle tree items")
		}
		items = append(items, merkleTreeItems[idx])
	}

	if len(merkleTreeOfRawSegments) > 0 {
		for i := range items {
			if i%encryptEverySegment == 0 && len(merkleTreeOfRawSegments) > 0 {
				items[i] = merkleTreeOfRawSegments[0]
				// remove the first element from merkleTreeOfRawSegments
				merkleTreeOfRawSegments = append(merkleTreeOfRawSegments[:0], merkleTreeOfRawSegments[1:]...)
			}
		}
	}

	if len(merkleTreeOfRawSegments) > 0 {
		return nil, errors.New("merkle tree of raw segements were not merged with the encrypted file's merkle tree")
	}

	return items, nil
}

// HashFileBlockSegments hashes all the file block segments and returns the merkle tree nodes.
// default totalSegments is 4096
func HashFileBlockSegments(filePath string, totalSegments int, randomSegments []int) ([]FileBlockHash, error) {
	if totalSegments == 0 {
		return nil, errors.New("total segments is zero")
	}
	inputFile, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open destination file for hashing its segments: %w", err)
	}
	defer inputFile.Close()
	fileStats, err := inputFile.Stat()
	if err != nil {
		return nil, fmt.Errorf("failed to get file stats: %w", err)
	}

	fileSize := int(fileStats.Size())

	if fileSize == 0 {
		return nil, errors.New("file size is zero")
	}

	howManySegments, segmentSizeBytes, totalSegmentsToEncrypt, encryptEverySegment := FileSegmentsInfo(fileSize, totalSegments, 0)
	ranges, ok := PrepareFileBlockRanges(0, howManySegments-1, fileSize, howManySegments, segmentSizeBytes, totalSegmentsToEncrypt, encryptEverySegment, randomSegments)
	if !ok {
		return nil, errors.New("failed to prepare file block/segment ranges")
	}

	sha256Sum := sha256.New()
	hashes := make([]FileBlockHash, 0)
	for _, v := range ranges {
		sha256Sum.Reset()
		_, err := inputFile.Seek(int64(v.from), 0)
		if err != nil {
			return nil, fmt.Errorf("failed to seek the file: %w", err)
		}
		diff := (v.to - v.from) + 1

		for diff > 0 {
			totalBytesRead := 0
			if diff > bufferSize {
				diff -= bufferSize
				totalBytesRead = bufferSize
			} else {
				totalBytesRead = diff
				diff -= diff
			}

			buf := make([]byte, totalBytesRead)
			n, err := inputFile.Read(buf)
			if n > 0 {
				sha256Sum.Write(buf[:n])
			}

			if err == io.EOF {
				break
			}

			if err != nil {
				return nil, fmt.Errorf("failed to read and copy data to buffer: %w", err)
			}
		}

		hash := sha256Sum.Sum(nil)
		fbh := FileBlockHash{X: make([]byte, len(hash))}
		copy(fbh.X, hash)

		hashes = append(hashes, fbh)
	}

	return hashes, nil
}

// FileSegmentsInfo returns the info about the segments of a file and number of encrypted segment given the file size.
func FileSegmentsInfo(fileSize int, howManySegments int, percentageToEncrypt int) (int, int, int, int) {
	if percentageToEncrypt > 100 {
		percentageToEncrypt = 100
	}
	segmentSizeBytes := 0
	sizeOverSegments := (float64(fileSize) / float64(howManySegments))

	if fileSize%howManySegments == 0 {
		// fits everything
		segmentSizeBytes = int(sizeOverSegments)
	} else {
		segmentSizeBytes = int(math.Round((sizeOverSegments) + 0.5))
	}

	fileSizeOverSegmentsize := float64(fileSize) / float64(segmentSizeBytes)
	newSegmentSize, fraction := math.Modf(fileSizeOverSegmentsize)
	if fraction > 0 {
		newSegmentSize++
	}

	howManySegments = int(newSegmentSize)

	if fileSize <= howManySegments {
		segmentSizeBytes = howManySegments
		howManySegments = 1
	}

	encryptionPercentage := (float64(percentageToEncrypt) / float64(100)) * float64(howManySegments)
	_, fracEncrypted := math.Modf(encryptionPercentage)
	totalSegmentsToEncrypt := 0
	if fracEncrypted > 0 {
		totalSegmentsToEncrypt = int(math.Round((encryptionPercentage) + 0.5))
	} else {
		totalSegmentsToEncrypt = int(math.Round(encryptionPercentage))
	}

	encryptEverySegment := 0
	if totalSegmentsToEncrypt > 0 {
		segmentsOverTotalSegmentsToEncrypt := float64(howManySegments) / float64(totalSegmentsToEncrypt)
		_, fraction := math.Modf(segmentsOverTotalSegmentsToEncrypt)
		if fraction > 0 {
			encryptEverySegment = int(math.Round((segmentsOverTotalSegmentsToEncrypt) + 0.5))
		} else {
			encryptEverySegment = int(math.Round(segmentsOverTotalSegmentsToEncrypt))
		}

		for {
			if encryptEverySegment*totalSegmentsToEncrypt > howManySegments {
				totalSegmentsToEncrypt--
			} else {
				break
			}
		}
	}

	return howManySegments, segmentSizeBytes, totalSegmentsToEncrypt, encryptEverySegment
}

// GetFileMerkleRootHash get a merkle root.
func GetFileMerkleRootHash(filePath string, totalSegments int, segmentsOrder []int) ([]byte, error) {
	fileBlockHashes, err := HashFileBlockSegments(filePath, totalSegments, segmentsOrder)
	if err != nil {
		return nil, fmt.Errorf("failed to get the list of merkle tree hashes")
	}
	merkleNodes := make([]merkletree.Content, len(fileBlockHashes))
	for i, v := range fileBlockHashes {
		merkleNodes[i] = v
	}

	t, err := merkletree.NewTree(merkleNodes)
	if err != nil {
		return nil, fmt.Errorf("failed to create a merkle tree from hash list: %w", err)
	}

	return t.MerkleRoot(), nil
}

// GetFileMerkleRootHashFromNodes get a merkle root from the content.
func GetFileMerkleRootHashFromNodes(fileBlockHashes []FileBlockHash) ([]byte, error) {
	merkleNodes := make([]merkletree.Content, len(fileBlockHashes))
	for i, v := range fileBlockHashes {
		merkleNodes[i] = v
	}

	t, err := merkletree.NewTree(merkleNodes)
	if err != nil {
		return nil, fmt.Errorf("failed to create a merkle tree from hash list: %w", err)
	}

	return t.MerkleRoot(), nil
}

// GenerateRandomIntSlice generates a random slice
// we always keep the last item same as original index
func GenerateRandomIntSlice(totalPerm int) []int {
	slice := mrand.Perm(totalPerm - 1)
	for i := range slice {
		// nolint:gosec
		bigNum, err := rand.Int(rand.Reader, big.NewInt(int64(i)+1))
		if err != nil {
			return nil
		}
		j := bigNum.Int64()
		slice[i], slice[j] = slice[j], slice[i]
	}
	slice = append(slice, totalPerm-1)
	return slice
}

// DefaultDataDir returns the default datadir.
func DefaultDataDir() string {
	home := HomeDir()
	if home != "" {
		switch runtime.GOOS {
		case "darwin":
			return filepath.Join(home, "Library", "filefilego_data")
		case "windows":
			return filepath.Join(home, "AppData", "Roaming", "filefilego_data")
		default:
			return filepath.Join(home, ".filefilego_data")
		}
	}
	return ""
}

// HomeDir returns the home directory.
func HomeDir() string {
	if home := os.Getenv("HOME"); home != "" {
		return home
	}
	if usr, err := user.Current(); err == nil {
		return usr.HomeDir
	}
	return ""
}

// DirExists checks if destination dir exists
func DirExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return info.IsDir()
}

// CreateDirectory creates a directory.
func CreateDirectory(path string) error {
	src, err := os.Stat(path)
	if os.IsNotExist(err) {
		errDir := os.MkdirAll(path, os.ModePerm)
		if errDir != nil {
			return fmt.Errorf("failed to create directory: %w", err)
		}
		return nil
	}

	if src.Mode().IsRegular() {
		return errors.New("path is a file")
	}

	return nil
}

// FileSize gets the file size
func FileSize(fullPath string) (int64, error) {
	fi, err := os.Stat(fullPath)
	if err != nil {
		return 0, fmt.Errorf("failed to get file stat: %w", err)
	}
	return fi.Size(), nil
}

// WriteToFile writes data to a file.
func WriteToFile(data []byte, filePath string) (string, error) {
	if err := os.MkdirAll(filepath.Dir(filePath), os.ModePerm); err != nil {
		return "", fmt.Errorf("failed to open path: %w", err)
	}
	file, err := os.Create(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to create path: %w", err)
	}
	defer file.Close()
	_, err = file.Write(data)
	if err != nil {
		return "", fmt.Errorf("failed to write data to path: %w", err)
	}
	return filePath, nil
}

// FileExists checks if destination file exists
func FileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}
