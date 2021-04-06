package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"io"
	"log"
	"math/rand"
	"os"

	"golang.org/x/crypto/chacha20"
)

func EncryptFile() {

	infile, err := os.Open("/home/filefilego/Desktop/ffg_binaries/FileFileGo Wallet-0.5.1-mac.zip")
	if err != nil {
		log.Fatal(err)
	}
	output, err := os.OpenFile("/home/filefilego/Desktop/ffgwallet.zip.encrypted", os.O_RDWR|os.O_CREATE, 0777)
	if err != nil {
		log.Fatal(err)
	}
	bufKey := make([]byte, 16)
	rand.Read(bufKey)

	block, err := aes.NewCipher(bufKey)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("size of iv ", block.BlockSize())
	iv := make([]byte, block.BlockSize())

	rand.Read(iv)
	stream := cipher.NewCTR(block, iv)

	encrypt(infile, output, stream)
	fmt.Println("successfully encrypted")

	chachaKey := make([]byte, 32)
	chachaNounce := make([]byte, 24)
	rand.Read(chachaKey)
	rand.Read(chachaNounce)
	stream, err = chacha20.NewUnauthenticatedCipher(chachaKey, chachaNounce)
	if err != nil {
		log.Fatal(err)
	}

	infile.Seek(0, 0)
	output.Close() // close previous
	output, err = os.OpenFile("/home/filefilego/Desktop/ffgwallet.zip.chacha.encrypted", os.O_RDWR|os.O_CREATE, 0777)
	defer output.Close()
	defer infile.Close()

	encrypt(infile, output, stream)

	fmt.Println("successfully encrypted using chacha")

}

func encrypt(inFile io.ReadSeekCloser, outputWriter io.WriteCloser, stream cipher.Stream) {
	// defer inFile.Close()
	// defer outputWriter.Close()

	buf := make([]byte, 2048)
	for {
		n, err := inFile.Read(buf)
		if n > 0 {
			stream.XORKeyStream(buf, buf[:n])
			outputWriter.Write(buf[:n])
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
