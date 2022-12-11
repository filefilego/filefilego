package cli

import (
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
				Name:   "create_node_key",
				Usage:  "create_node_key <passphrase>",
				Action: CreateNodeKeys,
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
	return nil
}

// CreateNodeKeys
func CreateNodeKeys(ctx *cli.Context) error {
	return nil
}
