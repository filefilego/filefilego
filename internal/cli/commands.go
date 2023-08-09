package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/filefilego/filefilego/common"
	"github.com/filefilego/filefilego/common/hexutil"
	"github.com/filefilego/filefilego/config"
	"github.com/filefilego/filefilego/crypto"
	"github.com/filefilego/filefilego/keystore"
	log "github.com/sirupsen/logrus"
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
			{
				Name:   "data_dir",
				Usage:  "data_dir",
				Action: ShowDefaultDataDir,
				Flags:  []cli.Flag{},
				Description: `
				Show default data dir`,
			},
		},
	}
)

// ListAddresses list the addresses on this node.
func ListAddresses(ctx *cli.Context) error {
	conf := config.New(ctx)
	if !common.DirExists(conf.Global.KeystoreDir) {
		return errors.New("keystore directory doesn't exist")
	}

	dirEntries, err := os.ReadDir(conf.Global.KeystoreDir)
	if err != nil {
		return fmt.Errorf("failed to read keystore directory: %w", err)
	}

	for i, entry := range dirEntries {
		if entry.Name() == "node_identity.json" {
			fileData, err := os.ReadFile(filepath.Join(conf.Global.KeystoreDir, entry.Name()))
			if err != nil {
				continue
			}

			nodeIDKeyaddrr := hexutil.ExtractHex(string(fileData))
			fmt.Printf("%d. Node Identity Key: %s\n", i, nodeIDKeyaddrr)
			continue
		}

		addrr := hexutil.ExtractHex(entry.Name())
		if addrr == "" {
			continue
		}

		fmt.Printf("%d. Address: %s\n", i, addrr)
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

// ShowDefaultDataDir prints the default data dir.
//
//nolint:all
func ShowDefaultDataDir(ctx *cli.Context) error {
	fmt.Printf("Default Data Directory::%s", common.DefaultDataDir())
	return nil
}
