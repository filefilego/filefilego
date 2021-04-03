package node

import (
	"fmt"
	"io"
	"math"
	"math/rand"
	"os"
	"sort"
	"time"

	log "github.com/sirupsen/logrus"
)

type FileBlockRange struct {
	mustEncrypt bool
	from        int
	to          int
}

func Range(from, to, fileSize, segmentSizeBytes, encryptEverySegment int, randomSlice []int) (fileRanges []FileBlockRange, _ bool) {

	// ranges := []FileBlockRange{}
	if to > fileSize-1 {
		return fileRanges, false
	}
	if from > to {
		return fileRanges, false
	}

	// ranges must be computed here
	// so we dont store info (FileBlockRange) for each single byte
	calcRanges := make(map[int]FileBlockRange)
	// lastBlock := 0
	for i := from; i <= to; i++ {
		div := i / segmentSizeBytes
		mod := i % segmentSizeBytes
		startIndex := randomSlice[div]*segmentSizeBytes + mod
		item, ok := calcRanges[div]
		if !ok {
			enc := div%encryptEverySegment == 0
			calcRanges[div] = FileBlockRange{
				// block: div,
				// remainder: mod,
				// finalIndex: randomSlice[div]*segmentSizeBytes + mod,
				mustEncrypt: enc,
				from:        startIndex,
				to:          startIndex,
			}

			if len(calcRanges) > 1 {
				f, _ := calcRanges[div-1]
				f.to = to
			}

		} else {
			item.to = startIndex
			calcRanges[div] = item
		}
	}

	keys := make([]int, len(calcRanges))
	i := 0
	for k := range calcRanges {
		keys[i] = k
		i++
	}
	sort.Ints(keys)

	for _, k := range keys {
		fileRanges = append(fileRanges, calcRanges[k])
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

func FileBlocksRandomizer(fileSize int) {

	segmentSizeBytes, howManySegments := 0, 24

	sizeOverSegments := (float64(fileSize) / float64(howManySegments))
	sizeModSegments := fileSize % howManySegments

	if sizeModSegments == 0 {
		// fits everything
		segmentSizeBytes = int(sizeOverSegments)
	} else {
		segmentSizeBytes = int(math.Round((sizeOverSegments) + 0.5))
	}

	if fileSize < howManySegments {
		// fmt.Println("single segment")
		segmentSizeBytes = howManySegments
		howManySegments = 1

	}

	fmt.Println("segmentSizeBytes: ", segmentSizeBytes)

	randomSlice := GenerateRandomIntSlice(howManySegments)

	// randomSlice = []int{1, 0, 2}
	// fmt.Println(randomSlice)

	totalSegmentsToEncrypt := int(math.Round(((float64(10) / float64(100)) * float64(howManySegments)) + 0.5))
	fmt.Println("totalSegmentsToEncrypt: ", totalSegmentsToEncrypt)

	encryptEverySegment := howManySegments / totalSegmentsToEncrypt

	ranges, _ := Range(0, 30, fileSize, segmentSizeBytes, encryptEverySegment, randomSlice)

	fmt.Println(ranges)

	enc := 0
	for _, v := range ranges {
		if v.mustEncrypt {
			enc++
		}
	}

	fmt.Println("Encrypted these many ", enc)
}

func FileManipulation() {
	infile, _ := os.Open("/home/filefilego/Desktop/txt.txt")
	infile.Seek(1, 0)
	for {

		buf := make([]byte, 2)

		n, err := infile.Read(buf)
		if n > 0 {
			fmt.Println("n: ", n)
			fmt.Println(string(buf))
		}

		if err == io.EOF {
			break
		}

		if err != nil {
			log.Printf("Read %d bytes: %v", n, err)
			break
		}
	}
}
