package cli

import (
	"bufio"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/briandowns/spinner"
	"github.com/fatih/color"
	"github.com/filefilego/filefilego/client"
	"github.com/filefilego/filefilego/common"
	"github.com/filefilego/filefilego/common/hexutil"
	"github.com/filefilego/filefilego/config"
	"github.com/rodaine/table"
	"github.com/schollz/progressbar/v3"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
)

// ClientCommand is exposes the client functionality to the cli
var ClientCommand = &cli.Command{
	Name:     "client",
	Usage:    "JSONRPC Client commands",
	Category: "Client",
	Description: `
	Interact with node using JSONRPC client`,
	Subcommands: []*cli.Command{
		{
			Name:   "endpoint",
			Usage:  "endpoint http://localhost:8090/rpc",
			Action: SetEndpoint,
			Flags:  []cli.Flag{},
			Description: `
			Sets the jsonrpc endpoint address`,
		},
		{
			Name:   "balance",
			Usage:  "balance <address>",
			Action: GetBalance,
			Flags:  []cli.Flag{},
			Description: `
			Get the balance of address`,
		},
		{
			Name:   "unlock_node_identity",
			Usage:  "unlock_node_identity <passphrase>",
			Action: UnlockNodeIdentity,
			Flags:  []cli.Flag{},
			Description: `
			Unlock node identity key and return a jwt token`,
		},
		{
			Name:   "query",
			Usage:  "query filehash1,filehash2,filehash3",
			Action: SendDataQuery,
			Flags:  []cli.Flag{},
			Description: `
			Sends a data query request`,
		},
		{
			Name:   "responses",
			Usage:  "responses <data_query_request_hash>",
			Action: CheckDataQueryResponses,
			Flags:  []cli.Flag{},
			Description: `
			Checks for data query responses given the data query request hash`,
		},
		{
			Name:   "responses",
			Usage:  "responses <data_query_request_hash>",
			Action: CheckDataQueryResponses,
			Flags:  []cli.Flag{},
			Description: `
			Checks for data query responses given the data query request hash`,
		},
		{
			Name:   "create_contracts",
			Usage:  "create_contracts <data_query_request_hash>",
			Action: CreateContractsFromDataQueryResponses,
			Flags:  []cli.Flag{},
			Description: `
			Creates a list of download contracts and prints their hashes`,
		},
		{
			Name:   "create_send_tx_with_contracts",
			Usage:  "create_send_tx_with_contracts <contract_hash1,contract_hash2> <jwt_access_token> <current_nounce> <each_tx_fee>",
			Action: CreateSendTXContracts,
			Flags:  []cli.Flag{},
			Description: `
			Prepares a tx with all the contracts`,
		},
		{
			Name:   "download",
			Usage:  "download <contract_hash1> <file_hash> <file_size>",
			Action: DownloadFile,
			Flags:  []cli.Flag{},
			Description: `
			Downloads a file given the contract hash and file hash`,
		},
	},
}

// SetEndpoint sets the endpoint to be used across the client commands.
func SetEndpoint(ctx *cli.Context) error {
	conf := config.New(ctx)
	_, err := common.WriteToFile([]byte(ctx.Args().First()), filepath.Join(conf.Global.DataDir, "client_jsonrpc_endpoint.txt"))
	if err != nil {
		return fmt.Errorf("failed to write endpoint to file")
	}
	return nil
}

func UnlockNodeIdentity(ctx *cli.Context) error {
	conf := config.New(ctx)
	endpoint, err := os.ReadFile(filepath.Join(conf.Global.DataDir, "client_jsonrpc_endpoint.txt"))
	if err != nil {
		return fmt.Errorf("failed to read client endpoint file: %w", err)
	}

	endpointBackup := ctx.Args().Get(1)
	if endpointBackup != "" {
		endpoint = []byte(endpointBackup)
	}

	ffgclient, err := client.New(string(endpoint), http.DefaultClient)
	if err != nil {
		return fmt.Errorf("failed to setup client: %w", err)
	}
	passphrase := ctx.Args().First()
	jwt, err := ffgclient.UnlockAddress(ctx.Context, "", passphrase, true)
	if err != nil {
		return fmt.Errorf("failed to unlock node identity key: %w", err)
	}

	fmt.Printf("Access token: %s\n", jwt)

	return nil
}

// GetBalance returns the balance of an address
func GetBalance(ctx *cli.Context) error {
	conf := config.New(ctx)
	endpoint, err := os.ReadFile(filepath.Join(conf.Global.DataDir, "client_jsonrpc_endpoint.txt"))
	if err != nil {
		return fmt.Errorf("failed to read client endpoint file: %w", err)
	}

	endpointBackup := ctx.Args().Get(1)
	if endpointBackup != "" {
		endpoint = []byte(endpointBackup)
	}

	ffgclient, err := client.New(string(endpoint), http.DefaultClient)
	if err != nil {
		return fmt.Errorf("failed to setup client: %w", err)
	}
	address := ctx.Args().First()
	balance, err := ffgclient.Balance(ctx.Context, address)
	if err != nil {
		return fmt.Errorf("failed to get address balance: %w", err)
	}

	headerFmt := color.New(color.FgGreen, color.Underline).SprintfFunc()
	columnFmt := color.New(color.FgYellow).SprintfFunc()

	tbl := table.New("Balance", "Balance hex", "Nounce", "Next Nounce")
	tbl.WithHeaderFormatter(headerFmt).WithFirstColumnFormatter(columnFmt)
	tbl.AddRow(balance.Balance+" FFG", balance.BalanceHex, balance.Nounce, balance.NextNounce)
	tbl.Print()
	fmt.Printf("\n")

	return nil
}

// CheckDataQueryResponses checks for data query responses.
func CheckDataQueryResponses(ctx *cli.Context) error {
	conf := config.New(ctx)
	endpoint, err := os.ReadFile(filepath.Join(conf.Global.DataDir, "client_jsonrpc_endpoint.txt"))
	if err != nil {
		return fmt.Errorf("failed to read client endpoint file: %w", err)
	}

	ffgclient, err := client.New(string(endpoint), http.DefaultClient)
	if err != nil {
		return fmt.Errorf("failed to setup client: %w", err)
	}
	dataQueryRequestHash := ctx.Args().First()
	fmt.Printf("\nData query hash: %s\n\n", dataQueryRequestHash)

	s := spinner.New(spinner.CharSets[43], 100*time.Millisecond)
	_ = s.Color("blue")
	s.Reverse()
	s.Prefix = "getting data responses from the network"
	s.Start()
	dataQueryResponse, err := ffgclient.CheckDataQueryResponse(ctx.Context, dataQueryRequestHash)
	time.Sleep(10 * time.Second)
	s.Stop()
	if err != nil {
		return fmt.Errorf("failed to check for data query responses: %w", err)
	}

	headerFmt := color.New(color.FgGreen, color.Underline).SprintfFunc()
	columnFmt := color.New(color.FgYellow).SprintfFunc()

	tbl := table.New("PeerID", "Available Files", "NA Files", "Fees per byte")
	tbl.WithHeaderFormatter(headerFmt).WithFirstColumnFormatter(columnFmt)

	for _, v := range dataQueryResponse.Responses {
		totalFees, err := hexutil.DecodeBig(v.FeesPerByte)
		if err != nil {
			continue
		}
		fees := common.FormatBigWithSeperator(common.LeftPad2Len(totalFees.Text(10), "0", 19), ".", 18)
		tbl.AddRow(v.FromPeerAddr, len(v.FileHashes), len(v.UnavailableFileHashes), fees+" FFG")
	}
	tbl.Print()

	fmt.Printf("\n")

	input := bufio.NewScanner(os.Stdin)
	input.Scan()
	return nil
}

// SendDataQuery sends a data query.
func SendDataQuery(ctx *cli.Context) error {
	conf := config.New(ctx)
	endpoint, err := os.ReadFile(filepath.Join(conf.Global.DataDir, "client_jsonrpc_endpoint.txt"))
	if err != nil {
		return fmt.Errorf("failed to read client endpoint file: %w", err)
	}

	ffgclient, err := client.New(string(endpoint), http.DefaultClient)
	if err != nil {
		return fmt.Errorf("failed to setup client: %w", err)
	}
	commadSeparatedFiles := ctx.Args().First()
	fileHashes := strings.Split(commadSeparatedFiles, ",")

	s := spinner.New(spinner.CharSets[43], 100*time.Millisecond)
	_ = s.Color("green")
	s.Prefix = "sending data query request to the network"
	s.Start()
	dataQueryRequestHash, err := ffgclient.SendDataQueryRequest(ctx.Context, fileHashes)
	time.Sleep(5 * time.Second)
	s.Stop()
	if err != nil {
		return fmt.Errorf("failed to send data query request: %w", err)
	}

	fmt.Printf("\nData query hash: %s\n\n", dataQueryRequestHash)

	s = spinner.New(spinner.CharSets[43], 100*time.Millisecond)
	_ = s.Color("blue")
	s.Reverse()
	s.Prefix = "getting data responses from the network"
	s.Start()
	dataQueryResponse, err := ffgclient.CheckDataQueryResponse(ctx.Context, dataQueryRequestHash)
	time.Sleep(10 * time.Second)
	s.Stop()
	if err != nil {
		return fmt.Errorf("failed to check for data query responses: %w", err)
	}

	headerFmt := color.New(color.FgGreen, color.Underline).SprintfFunc()
	columnFmt := color.New(color.FgYellow).SprintfFunc()

	tbl := table.New("PeerID", "Available Files", "NA Files", "Fees per byte")
	tbl.WithHeaderFormatter(headerFmt).WithFirstColumnFormatter(columnFmt)

	for _, v := range dataQueryResponse.Responses {
		totalFees, err := hexutil.DecodeBig(v.FeesPerByte)
		if err != nil {
			continue
		}
		fees := common.FormatBigWithSeperator(common.LeftPad2Len(totalFees.Text(10), "0", 19), ".", 18)
		tbl.AddRow(v.FromPeerAddr, len(v.FileHashes), len(v.UnavailableFileHashes), fees+" FFG")
	}
	tbl.Print()

	fmt.Printf("\n")

	input := bufio.NewScanner(os.Stdin)
	input.Scan()
	return nil
}

// CreateContractsFromDataQueryResponses creates a list of contracts given the data query request hash.
func CreateContractsFromDataQueryResponses(ctx *cli.Context) error {
	conf := config.New(ctx)
	endpoint, err := os.ReadFile(filepath.Join(conf.Global.DataDir, "client_jsonrpc_endpoint.txt"))
	if err != nil {
		return fmt.Errorf("failed to read client endpoint file: %w", err)
	}

	ffgclient, err := client.New(string(endpoint), http.DefaultClient)
	if err != nil {
		return fmt.Errorf("failed to setup client: %w", err)
	}
	dataQueryRequestHash := ctx.Args().First()
	fmt.Printf("\nData query hash: %s\n\n", dataQueryRequestHash)

	contractHashes, err := ffgclient.CreateContractsFromDataQueryResponses(ctx.Context, dataQueryRequestHash)
	if err != nil {
		return fmt.Errorf("failed to create contracts from data query responses: %w", err)
	}

	for i, v := range contractHashes {
		fmt.Printf("contract number %d hash: %s\n", i, v)
	}

	return nil
}

// CreateSendTXContracts creates transactions with download contracts.
func CreateSendTXContracts(ctx *cli.Context) error {
	conf := config.New(ctx)
	endpoint, err := os.ReadFile(filepath.Join(conf.Global.DataDir, "client_jsonrpc_endpoint.txt"))
	if err != nil {
		return fmt.Errorf("failed to read client endpoint file: %w", err)
	}

	ffgclient, err := client.New(string(endpoint), http.DefaultClient)
	if err != nil {
		return fmt.Errorf("failed to setup client: %w", err)
	}

	downloadContractHashes := ctx.Args().First()
	accessToken := ctx.Args().Get(1)
	if accessToken == "" {
		return errors.New("access token is empty")
	}

	currentNounce := ctx.Args().Get(2)
	if currentNounce == "" {
		return errors.New("current nounce is empty")
	}

	eachTxFees := ctx.Args().Get(3)
	if eachTxFees == "" {
		return errors.New("each tx fees is empty")
	}

	contractHashes := strings.Split(downloadContractHashes, ",")

	if len(contractHashes) == 0 {
		return errors.New("contract hashes are empty")
	}

	for _, v := range contractHashes {
		sentContractToHosterAndVerifier, err := ffgclient.SendContractToFileHosterAndVerifier(ctx.Context, v)
		if err != nil || !sentContractToHosterAndVerifier {
			log.Errorf("failed to send contracts to verifier and hoster: %v", err)
			continue
		}
	}

	jsonEncodedRawTransactions, _, err := ffgclient.CreateTransactionsWithDataPayloadFromContractHashes(ctx.Context, contractHashes, accessToken, currentNounce, eachTxFees)
	if err != nil {
		return fmt.Errorf("failed to create the transactions: %w", err)
	}

	for _, v := range jsonEncodedRawTransactions {
		txResponse, err := ffgclient.SendRawTransaction(ctx.Context, v)
		if err != nil {
			log.Errorf("failed to send raw transaction: %v", err)
		}

		fmt.Printf("Transaction sent: %s\n", txResponse.Transaction.Hash)
	}

	return nil
}

func DownloadFile(ctx *cli.Context) error {
	conf := config.New(ctx)
	endpoint, err := os.ReadFile(filepath.Join(conf.Global.DataDir, "client_jsonrpc_endpoint.txt"))
	if err != nil {
		return fmt.Errorf("failed to read client endpoint file: %w", err)
	}

	ffgclient, err := client.New(string(endpoint), http.DefaultClient)
	if err != nil {
		return fmt.Errorf("failed to setup client: %w", err)
	}

	downloadContractHash := ctx.Args().First()
	fileHash := ctx.Args().Get(1)
	fileSize := ctx.Args().Get(2)

	sizeOfFile, err := strconv.ParseUint(fileSize, 10, 64)
	if err != nil {
		return fmt.Errorf("failed to parse file size: %w", err)
	}

	stats, err := ffgclient.DownloadFile(ctx.Context, downloadContractHash, fileHash, sizeOfFile)
	if err != nil {
		return fmt.Errorf("failed to start downloading file: %w", err)
	}

	fmt.Println("Download stats: ", stats)
	bar := progressbar.NewOptions64(int64(sizeOfFile),
		// progressbar.OptionSetWriter(ansi.NewAnsiStdout()),
		progressbar.OptionEnableColorCodes(true),
		progressbar.OptionShowBytes(true),
		progressbar.OptionSetWidth(15),
		progressbar.OptionSetDescription("[cyan][1/3][reset] Downloading file "+fileHash+"..."),
		progressbar.OptionSetTheme(progressbar.Theme{
			Saucer:        "[green]=[reset]",
			SaucerHead:    "[green]>[reset]",
			SaucerPadding: " ",
			BarStart:      "[",
			BarEnd:        "]",
		}))

	bytesTransfered := uint64(0)
	for bytesTransfered < sizeOfFile {
		prog, err := ffgclient.DownloadFileProgress(ctx.Context, downloadContractHash, fileHash)
		if err != nil {
			log.Errorf("failed to get file progress: %v", err)
		}
		_ = bar.Set(int(prog.BytesTransfered))
		bytesTransfered += prog.BytesTransfered
		time.Sleep(5 * time.Millisecond)
	}

	return nil
}
