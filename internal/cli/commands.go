package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/filefilego/filefilego/config"
	"github.com/filefilego/filefilego/internal/crypto"
	"github.com/filefilego/filefilego/internal/keystore"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
)

var (
	AppHelpTemplate = `NAME:
	{{.Name}} - {{.Usage}}
	Copyright 2022 The FileFileGo team
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

	AccountCommand = &cli.Command{
		Name:     "account",
		Usage:    "Manage accounts",
		Category: "Account",
		Description: `
					Manage accounts, create, delete load etc.`,
		Subcommands: []*cli.Command{
			{
				Name:   "create",
				Usage:  "create <passphrase>",
				Action: CreateAccount,
				Flags:  []cli.Flag{},
				Description: `
				Creates a new account from passphrase`,
			},
			{
				Name:   "info",
				Usage:  "info <keypath> <passphrase>",
				Action: GetAccountInfo,
				Flags:  []cli.Flag{},
				Description: `
				Get key information`,
			},
			{
				Name:   "create_node_key",
				Usage:  "create_node_key <passphrase>",
				Action: CreateNodeKey,
				Flags:  []cli.Flag{},
				Description: `
				Creates a a node key`,
			},
			{
				Name:   "list",
				Usage:  "list",
				Action: ListAccounts,
				Flags:  []cli.Flag{},
				Description: `
				lists all available accounts`,
			},
		},
	}
)

// ListAccounts
func ListAccounts(ctx *cli.Context) error {
	return nil
}

// CreateAccount
func CreateAccount(ctx *cli.Context) error {
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

// GetAccountInfo gets the account info.
func GetAccountInfo(ctx *cli.Context) error {
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

// CreateNodeKeys
func CreateNodeKey(ctx *cli.Context) error {
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
