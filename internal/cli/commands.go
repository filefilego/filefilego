package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"

	"github.com/filefilego/filefilego/common"
	"github.com/filefilego/filefilego/common/hexutil"
	"github.com/filefilego/filefilego/config"
	"github.com/filefilego/filefilego/crypto"
	"github.com/filefilego/filefilego/database"
	"github.com/filefilego/filefilego/keystore"
	"github.com/filefilego/filefilego/storage"
	log "github.com/sirupsen/logrus"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/urfave/cli/v2"
)

var (
	AppHelpTemplate = `NAME:
	{{.Name}} - {{.Usage}}
	Copyright 2023 The FileFileGo team
	USAGE:
	{{.HelpName}} {{if .VisibleFlags}}[global options]{{end}}{{if .Commands}} command [command options]{{end}} {{if .ArgsUsage}}{{.ArgsUsage}}{{else}}[arguments...]{{end}}
	{{if len .Authors}}
	AUTHOR:
	{{range .Authors}}{{ . }}{{end}}
	{{end}}{{if .Version}}
	VERSION:
	  {{.Version}}
	  {{end}}{{if .Commands}}
	COMMANDS:
	{{range .Commands}}{{if not .HideHelp}}   {{join .Names ", "}}{{ "\t"}}{{.Usage}}{{ "\n" }}{{end}}{{end}}{{end}}{{if .VisibleFlags}}
	GLOBAL OPTIONS:
	{{range .VisibleFlags}}{{.}}
	{{end}}{{end}}{{if .Copyright }}
	COPYRIGHT:
	   {{.Copyright}}
	{{end}}
	`

	AddressCommand = &cli.Command{
		Name:     "address",
		Usage:    "Manage addresses",
		Category: "Addresss",
		Description: `
					Manage addresses, create, delete load etc.`,
		Subcommands: []*cli.Command{
			{
				Name:   "create",
				Usage:  "create <passphrase>",
				Action: CreateAddress,
				Flags:  []cli.Flag{},
				Description: `
				Creates a new address from passphrase`,
			},
			{
				Name:   "info",
				Usage:  "info <keypath> <passphrase>",
				Action: GetAddressInfo,
				Flags:  []cli.Flag{},
				Description: `
				Get key information`,
			},
			{
				Name:   "create_node_key",
				Usage:  "create_node_key <passphrase>",
				Action: CreateNodeIDKey,
				Flags:  []cli.Flag{},
				Description: `
				Creates a new node identity key`,
			},
			{
				Name:   "list",
				Usage:  "list",
				Action: ListAddresses,
				Flags:  []cli.Flag{},
				Description: `
				Lists all available addresses`,
			},
		},
	}

	StorageCommand = &cli.Command{
		Name:     "storage",
		Usage:    "Manage file storage",
		Category: "Storage",
		Description: `
					Manage storage, add or remove files to local storage`,
		Subcommands: []*cli.Command{
			{
				Name:   "add",
				Usage:  "add <filepath>",
				Action: AddFile,
				Flags:  []cli.Flag{},
				Description: `
				Add a new file to storage given its full path`,
			},
			{
				Name:   "get",
				Usage:  "get <filehash>",
				Action: GetFile,
				Flags:  []cli.Flag{},
				Description: `
				Get file's metadata from file hash`,
			},
		},
	}
)

// GetFile gets file's metadata from hash
func GetFile(ctx *cli.Context) error {
	conf := config.New(ctx)
	db, err := leveldb.OpenFile(filepath.Join(conf.Global.DataDir, "blockchain.db"), nil)
	if err != nil {
		return fmt.Errorf("failed to open leveldb database file: %w", err)
	}
	defer db.Close()
	globalDB, err := database.New(db)
	if err != nil {
		return fmt.Errorf("failed to setup global database: %w", err)
	}

	s, err := storage.New(globalDB, conf.Global.StorageDir, true, conf.Global.StorageToken, conf.Global.StorageFileMerkleTreeTotalSegments)
	if err != nil {
		return fmt.Errorf("failed to setup storage: %w", err)
	}

	fileHash := ctx.Args().First()

	fileMetadata, err := s.GetFileMetadata(fileHash)
	if err != nil {
		return fmt.Errorf("failed to find file: %w", err)
	}

	log.Infof("MerkleRootHash:\t%s", fileMetadata.MerkleRootHash)
	log.Infof("Hash:\t%s", fileMetadata.Hash)
	log.Infof("FilePath:\t%s", fileMetadata.FilePath)
	log.Infof("Size:\t%d", fileMetadata.Size)

	return nil
}

// AddFile adds a file to local storage.
func AddFile(ctx *cli.Context) error {
	conf := config.New(ctx)
	db, err := leveldb.OpenFile(filepath.Join(conf.Global.DataDir, "blockchain.db"), nil)
	if err != nil {
		return fmt.Errorf("failed to open leveldb database file: %w", err)
	}
	defer db.Close()
	globalDB, err := database.New(db)
	if err != nil {
		return fmt.Errorf("failed to setup global database: %w", err)
	}

	s, err := storage.New(globalDB, conf.Global.StorageDir, true, conf.Global.StorageToken, conf.Global.StorageFileMerkleTreeTotalSegments)
	if err != nil {
		return fmt.Errorf("failed to setup storage: %w", err)
	}

	fPath := ctx.Args().First()

	filePath, err := filepath.Abs(fPath)
	if err != nil {
		return fmt.Errorf("failed to get file's absolute path: %w", err)
	}

	fileSize, err := common.FileSize(filePath)
	if err != nil {
		return fmt.Errorf("failed to get file's size: %w", err)
	}

	fHash, err := crypto.Sha1File(filePath)
	if err != nil {
		return fmt.Errorf("failed to get file's hash: %w", err)
	}

	howManySegments, _, _, _ := common.FileSegmentsInfo(int(fileSize), conf.Global.StorageFileMerkleTreeTotalSegments, 0)
	orderedSlice := make([]int, howManySegments)
	for i := 0; i < howManySegments; i++ {
		orderedSlice[i] = i
	}

	fMerkleRootHash, err := common.GetFileMerkleRootHash(filePath, conf.Global.StorageFileMerkleTreeTotalSegments, orderedSlice)
	if err != nil {
		return fmt.Errorf("failed to get file's merkle root hash: %w", err)
	}

	fileMetadata := storage.FileMetadata{
		MerkleRootHash: hexutil.Encode(fMerkleRootHash),
		Hash:           fHash,
		FilePath:       filePath,
		Size:           fileSize,
	}

	err = s.SaveFileMetadata("", fHash, fileMetadata)
	if err != nil {
		return fmt.Errorf("failed to save file's metadata: %w", err)
	}

	log.Infof("MerkleRootHash:\t%s", fileMetadata.MerkleRootHash)
	log.Infof("Hash:\t%s", fileMetadata.Hash)
	log.Infof("FilePath:\t%s", fileMetadata.FilePath)
	log.Infof("Size:\t%d", fileMetadata.Size)

	return nil
}

// ListAddresses list the addresses on this node.
func ListAddresses(ctx *cli.Context) error {
	conf := config.New(ctx)
	if !common.DirExists(conf.Global.KeystoreDir) {
		return errors.New("keystore directory doesn't exist")
	}

	f, err := os.Open(conf.Global.KeystoreDir)
	if err != nil {
		return fmt.Errorf("failed to read keystore directory: %w", err)
	}
	fileInfo, err := f.Readdir(-1)
	f.Close()
	if err != nil {
		return fmt.Errorf("failed to read keystore directory: %w", err)
	}

	for i, file := range fileInfo {
		if file.Name() == "node_identity.json" {
			fileData, err := os.ReadFile(filepath.Join(conf.Global.KeystoreDir, file.Name()))
			if err != nil {
				continue
			}

			nodeIDKeyaddrr := extractHex(string(fileData))
			fmt.Printf("%d. Node Identity Key: 0x%s\n", i, nodeIDKeyaddrr)
			continue
		}

		addrr := extractHex(file.Name())
		if addrr == "" {
			continue
		}

		fmt.Printf("%d. Address: 0x%s\n", i, addrr)
	}

	return nil
}

// CreateAddress creates a new keystore file.
func CreateAddress(ctx *cli.Context) error {
	conf := config.New(ctx)
	store, err := keystore.New(conf.Global.KeystoreDir, []byte{1})
	if err != nil {
		return fmt.Errorf("failed to create keystore: %w", err)
	}
	keyPath, err := store.CreateKey(ctx.Args().First())
	if err != nil {
		return fmt.Errorf("failed to create key: %w", err)
	}
	log.Infof("key created at: %s", keyPath)
	return nil
}

// GetAddressInfo gets the address info.
func GetAddressInfo(ctx *cli.Context) error {
	keyPath := ctx.Args().Get(0)
	passphrase := ctx.Args().Get(1)

	data, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("failed to read key path: %w", err)
	}
	key, err := keystore.UnmarshalKey(data, passphrase)
	if err != nil {
		return fmt.Errorf("failed to unmarshal key: %w", err)
	}

	pubKeyHex, err := crypto.PublicKeyToHex(key.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to get public key hex: %w", err)
	}

	privKeyHex, err := crypto.PrivateKeyToHex(key.PrivateKey)
	if err != nil {
		return fmt.Errorf("failed to get private key hex: %w", err)
	}

	log.Infof("Address:\t%s", key.Address)
	log.Infof("PublicKey:\t%s", pubKeyHex)
	log.Infof("PrivateKey:\t%s", privKeyHex)

	return nil
}

// CreateNodeIDKey creates a node key identity file.
func CreateNodeIDKey(ctx *cli.Context) error {
	conf := config.New(ctx)
	store, err := keystore.New(conf.Global.KeystoreDir, []byte{1})
	if err != nil {
		return fmt.Errorf("failed to create keystore: %w", err)
	}
	keyPath, err := store.CreateKey(ctx.Args().First())
	if err != nil {
		return fmt.Errorf("failed to create key: %w", err)
	}

	err = os.Rename(keyPath, filepath.Join(conf.Global.KeystoreDir, "node_identity.json"))
	if err != nil {
		return fmt.Errorf("failed to rename node identity key file: %w", err)
	}

	return nil
}

func extractHex(s string) string {
	r := regexp.MustCompile(`0x([A-Fa-f0-9]{6,})`)
	matches := r.FindStringSubmatch(s)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}
