package node

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"fmt"
	"io"
	"math"
	"math/rand"
	"os"
	"time"

	"github.com/cbergoon/merkletree"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/sha3"
)

type FileBlockRange struct {
	mustEncrypt bool
	from        int
	to          int
}

type FileBlockContent struct {
	x []byte
}

//CalculateHash hashes the values of a TestContent
func (t FileBlockContent) CalculateHash() ([]byte, error) {
	h := sha256.New()
	if _, err := h.Write(t.x); err != nil {
		return nil, err
	}

	return h.Sum(nil), nil
}

//Equals tests for equality of two Contents
func (t FileBlockContent) Equals(other merkletree.Content) (bool, error) {
	return bytes.Equal(t.x, other.(FileBlockContent).x), nil
}

func GetFileMerkleHash(filePath string) (merkleRoot []byte, _ error) {
	fileBlockHashes, err := HashFileBlocksBySegment(filePath)
	if err != nil {
		return merkleRoot, err
	}
	t, err := merkletree.NewTree(fileBlockHashes)
	if err != nil {
		return merkleRoot, err
	}
	return t.MerkleRoot(), nil
}

func HashFileBlocksBySegment(filePath string) (hashes []merkletree.Content, _ error) {

	uploadedFile, err := os.Open(filePath)
	if err != nil {
		return hashes, err
	}
	defer uploadedFile.Close()

	fstats, err := uploadedFile.Stat()

	if err != nil {
		return hashes, err
	}

	fileSize := int(fstats.Size())
	// create the root
	howManySegments, segmentSizeBytes, _, _ := GetFileSegmentsMetadata(fileSize)

	orderedSlice := []int{}
	for i := 0; i < howManySegments; i++ {
		orderedSlice = append(orderedSlice, i)
	}

	ranges, _ := PrepareOffsetRanges(0, fileSize-1, fileSize, segmentSizeBytes, orderedSlice)

	bufferSize := 8192 //8kb

	sha256Sum := sha3.New256()

	for _, v := range ranges {
		sha256Sum.Reset()
		uploadedFile.Seek(int64(v.from), 0)
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
			n, err := uploadedFile.Read(buf)
			if err != nil {
				log.Warn(err)
			}
			if n > 0 {
				// do the sha sum
				sha256Sum.Write(buf[:n])
			}

			if err == io.EOF {
				log.Error("EOF while generating merkle root", err)
				break
			}
		}

		hashes = append(hashes, FileBlockContent{x: sha256Sum.Sum(nil)})
	}

	return hashes, nil
}

func PrepareOffsetRanges(from, to, fileSize, segmentSizeBytes int, randomSlice []int) (fileRanges []FileBlockRange, _ bool) {
	if to > fileSize-1 {
		return fileRanges, false
	}
	if from > to {
		return fileRanges, false
	}

	tmpDivision := from / segmentSizeBytes
	start := randomSlice[tmpDivision]*segmentSizeBytes + (from % segmentSizeBytes)
	enteredLoop := false

	for i := from + 1; i <= to; i++ {
		enteredLoop = true
		div := i / segmentSizeBytes

		if div != tmpDivision {
			fileRanges = append(fileRanges, FileBlockRange{
				from: start,
				to:   randomSlice[(i-1)/segmentSizeBytes]*segmentSizeBytes + ((i - 1) % segmentSizeBytes),
			})

			mod := i % segmentSizeBytes
			start = randomSlice[div]*segmentSizeBytes + mod
			tmpDivision = div

			if i == to {
				fileRanges = append(fileRanges, FileBlockRange{
					from: start,
					to:   randomSlice[i/segmentSizeBytes]*segmentSizeBytes + (i % segmentSizeBytes),
				})
			}

			// makes magic (skips until end of the segments)
			// without this, would take forever
			if i+segmentSizeBytes-1 < to {
				i = i + segmentSizeBytes - 1
			}

		} else if i == to {
			// last
			fileRanges = append(fileRanges, FileBlockRange{
				from: start,
				to:   randomSlice[i/segmentSizeBytes]*segmentSizeBytes + (i % segmentSizeBytes),
			})

		}
	}

	if !enteredLoop {
		fileRanges = append(fileRanges, FileBlockRange{
			from: start,
			to:   start,
		})
	}

	return fileRanges, true
}

// GenerateRandomIntSlice generates a random slice
// we always keep the last item same as original index
func GenerateRandomIntSlice(totalPerm int) []int {
	source := rand.NewSource(time.Now().UnixNano())
	random := rand.New(source)
	slice := rand.Perm(totalPerm - 1)
	for i := range slice {
		j := random.Intn(i + 1)
		slice[i], slice[j] = slice[j], slice[i]
	}
	slice = append(slice, totalPerm-1)
	return slice
}

func GetFileSegmentsMetadata(fileSize int) (int, int, int, int) {
	percentageToEncrypt := 4

	segmentSizeBytes, howManySegments := 0, 4096
	sizeOverSegments := (float64(fileSize) / float64(howManySegments))
	sizeModSegments := fileSize % howManySegments

	if sizeModSegments == 0 {
		// fits everything
		segmentSizeBytes = int(sizeOverSegments)
	} else {
		segmentSizeBytes = int(math.Round((sizeOverSegments) + 0.5))
	}

	fileSizeOverSegsize := float64(fileSize) / float64(segmentSizeBytes)
	newSegmentSize, frc := math.Modf(fileSizeOverSegsize)
	if frc > 0 {
		newSegmentSize += 1
	}

	howManySegments = int(newSegmentSize)

	if fileSize < howManySegments {
		segmentSizeBytes = howManySegments
		howManySegments = 1
	}

	enPer := (float64(percentageToEncrypt) / float64(100)) * float64(howManySegments)
	_, frac := math.Modf(enPer)
	totalSegmentsToEncrypt := 0
	if frac > 0 {
		totalSegmentsToEncrypt = int(math.Round((enPer) + 0.5))
	} else {
		totalSegmentsToEncrypt = int(math.Round(enPer))
	}

	encryptEverySegment := howManySegments / totalSegmentsToEncrypt

	// need this so when encryptEverySegment is zero, avoid division by zero
	if encryptEverySegment == 0 {
		encryptEverySegment = 1
	}

	return howManySegments, segmentSizeBytes, totalSegmentsToEncrypt, encryptEverySegment
}

// GetFileBlockOrderAndEncryptionList returns
func GetFileBlockOrderAndEncryptionList(fileSize, from, to int) ([]FileBlockRange, []int, int, int, int, int) {

	howManySegments, segmentSizeBytes, totalSegmentsToEncrypt, encryptEverySegment := GetFileSegmentsMetadata(fileSize)
	randomSlice := GenerateRandomIntSlice(howManySegments)
	ranges, _ := PrepareOffsetRanges(from, to, fileSize, segmentSizeBytes, randomSlice)
	totalSegmentsToEncryptTmp := totalSegmentsToEncrypt

	// which blocks to encrypt
	enc := 0
	for i, v := range ranges {
		div := v.from / segmentSizeBytes
		if div%encryptEverySegment == 0 && totalSegmentsToEncrypt != 0 {
			totalSegmentsToEncrypt--
			enc++
			ranges[i].mustEncrypt = true
		}
	}

	return ranges, randomSlice, segmentSizeBytes, howManySegments, totalSegmentsToEncryptTmp, encryptEverySegment
}

func FileManipulation() {

	// AES
	bufKey := make([]byte, 16)
	rand.Read(bufKey)

	block, err := aes.NewCipher(bufKey)
	if err != nil {
		log.Fatal(err)
	}

	iv := make([]byte, block.BlockSize())

	iv2 := make([]byte, block.BlockSize())

	rand.Read(iv)
	copy(iv2, iv)
	stream := cipher.NewCTR(block, iv)
	// END of AES

	infile, _ := os.Open("/home/filefilego/Desktop/a.AppImage")
	output, _ := os.OpenFile("/home/filefilego/Desktop/a.AppImage.enc", os.O_RDWR|os.O_CREATE, 0777)
	output2, _ := os.OpenFile("/home/filefilego/Desktop/a.decrypted.AppImage", os.O_RDWR|os.O_CREATE, 0777)
	info, _ := infile.Stat()
	ranges, randomSlice, segmentSizeBytes, howManySegments, totalSegmentsToEncrypt, _ := GetFileBlockOrderAndEncryptionList(int(info.Size()), 0, int(info.Size())-1)

	// fmt.Println("ranges ", ranges)

	bufferSize := 8192 //8kb
	for _, v := range ranges {
		infile.Seek(int64(v.from), 0)

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
			n, err := infile.Read(buf)
			if err != nil {
				log.Warn(err)
			}
			if n > 0 {
				if v.mustEncrypt {
					stream.XORKeyStream(buf, buf[:n])
				}
				okn, err := output.Write(buf[:n])
				if okn != n {
					log.Fatal("problem writing same as read bytes")
				}
				if err != nil {
					log.Fatal("problem with writing to ourput file")

				}
			} else {
				log.Warn("this triggered n > 0")
			}

			if err == io.EOF {
				log.Fatal("problem reading from original EOF")
			}

			if err != nil {
				log.Fatalf("Read %d bytes: %v", n, err)

			}

		}

	}

	output.Seek(0, 0)

	stream2 := cipher.NewCTR(block, iv2)

	fmt.Println("descrypting segments: ", totalSegmentsToEncrypt)

	for i, v := range ranges {
		if v.mustEncrypt {

			from := i * segmentSizeBytes
			to := from + segmentSizeBytes - 1
			diff := (to - from) + 1
			totalOffset := 0
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
				output.Seek(int64(from+totalOffset), 0)
				n, err := output.Read(buf)
				output.Seek(int64(from+totalOffset), 0)

				if err != nil {
					log.Warn(err)
				}
				if n > 0 {
					stream2.XORKeyStream(buf, buf[:n])
					totalOffset += n
					okn, err := output.Write(buf[:n])
					if okn != n {
						log.Fatal("problem writing same as read bytes")
					}
					if err != nil {
						log.Fatal("problem with writing to ourput file")

					}
				} else {
					log.Warn("this triggered n > 0")
				}

			}
			output.Sync()
		}
	}

	fmt.Print("restoring original file")

	output.Seek(0, 0)

	for i := 0; i < howManySegments; i++ {
		idx := -1
		for j, v := range randomSlice {
			if v == i {
				idx = j
				break
			}
		}

		from := idx * segmentSizeBytes
		to := from + segmentSizeBytes - 1

		output.Seek(int64(from), 0)
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

			n, err := output.Read(buf)
			if n > 0 {
				okn, err := output2.Write(buf[:n])
				if err != nil {
					log.Warn(err)
					break
				}
				if okn != n {
					log.Fatal("problem writing same as read bytes")
				}
				if err != nil {
					log.Fatal("problem with writing to ourput file")
				}
			}

			if err == io.EOF {
				continue
			}

			if err != nil {
				log.Fatalf("Read %d bytes: %v", n, err)

			}

		}

	}

}
