package cli

import (
	"bufio"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
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
			Name:   "upload",
			Usage:  "upload <filepath> <storage_access_token> <node_hash>",
			Action: UploadFile,
			Flags:  []cli.Flag{},
			Description: `
			Uploads a file to a node. The node_hash is optional, you can omit it if you dont want to reference a channel node item on the blockchain`,
		},
		{
			Name:   "get_storage_token",
			Usage:  "get_storage_token <admin_token>",
			Action: GetStorageAccessToken,
			Flags:  []cli.Flag{},
			Description: `
			Gets a storage access token derived from the admin token`,
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
			Name:   "send_transaction",
			Usage:  "send_transaction <access_token> <nounce> <data> <from_address> <to_address> <tx_value> <tx_fees>",
			Action: SendTransaction,
			Flags:  []cli.Flag{},
			Description: `
			Sends a transaction given the access token, nouce, data, from and to with the value and fees`,
		},
		{
			Name:   "unlock_address",
			Usage:  "unlock_address <address> <passphrase>",
			Action: UnlockAddress,
			Flags:  []cli.Flag{},
			Description: `
			Unlock an address with the given passphrase and returns a jwt token`,
		},
		{
			Name:   "query",
			Usage:  "query filehash1,filehash2,filehash3",
			Action: SendDataQuery,
			Flags:  []cli.Flag{},
			Description: `
			Sends a data query request by a comma separate list of file hashes`,
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
			Usage:  "download <contract_hash1> <file_hash>",
			Action: DownloadFile,
			Flags:  []cli.Flag{},
			Description: `
			Downloads a file given the contract hash and file hash`,
		},
		{
			Name:   "send_file_signature_to_verifier",
			Usage:  "send_file_signature_to_verifier <contract_hash1> <file_hash>",
			Action: SendFileMerkleTreeNodesToVerifier,
			Flags:  []cli.Flag{},
			Description: `
			Creates a merkle tree nodes of downloaded file and sends to verifier`,
		},
		{
			Name:   "decrypt_files",
			Usage:  "decrypt_files <contract_hash> <file_hash1,file_hash2> <file1_merkle_root_hash,file2_merkle_root_hash> <restore_full_path_file1,restore_full_path_file2>",
			Action: DecryptAllFiles,
			Flags:  []cli.Flag{},
			Description: `
			Decrypts and restores the given files to the supplied destinations`,
		},
		{
			Name:   "host_info",
			Usage:  "host_info",
			Action: GetHostInfo,
			Flags:  []cli.Flag{},
			Description: `
			Gets the host information including addresses, peerID and peer count`,
		},
	},
}

// GetHostInfo gets host's info
func GetHostInfo(ctx *cli.Context) error {
	conf := config.New(ctx)
	endpoint, err := os.ReadFile(filepath.Join(conf.Global.DataDir, "client_jsonrpc_endpoint.txt"))
	if err != nil {
		return fmt.Errorf("failed to read client endpoint file: %w", err)
	}

	ffgclient, err := client.New(string(endpoint), http.DefaultClient)
	if err != nil {
		return fmt.Errorf("failed to setup client: %w", err)
	}

	response, err := ffgclient.GetHostInfo(ctx.Context)
	if err != nil {
		return fmt.Errorf("failed to get node's host info: %w", err)
	}

	fmt.Println("Address: ", response.Address)
	fmt.Println("PeerID: ", response.PeerID)
	fmt.Println("Peers count: ", response.PeerCount)

	return nil
}

// UploadFile uploads a file.
func UploadFile(ctx *cli.Context) error {
	conf := config.New(ctx)
	endpoint, err := os.ReadFile(filepath.Join(conf.Global.DataDir, "client_jsonrpc_endpoint.txt"))
	if err != nil {
		return fmt.Errorf("failed to read client endpoint file: %w", err)
	}

	ffgclient, err := client.New(string(endpoint), http.DefaultClient)
	if err != nil {
		return fmt.Errorf("failed to setup client: %w", err)
	}

	filePath := ctx.Args().First()
	if filePath == "" {
		return errors.New("file path is empty")
	}

	storageAccessToken := ctx.Args().Get(1)
	if storageAccessToken == "" {
		return errors.New("storage access token is empty")
	}

	nodeHash := ctx.Args().Get(2)

	response, err := ffgclient.UploadFile(ctx.Context, filePath, nodeHash, storageAccessToken)
	if err != nil {
		return fmt.Errorf("failed to upload file: %w", err)
	}

	if response.Error != "" {
		return fmt.Errorf("failed to upload file: %s", response.Error)
	}

	fmt.Println("FileName: ", response.FileName)
	fmt.Println("FileHash: ", response.FileHash)
	fmt.Println("MerkleRoot: ", response.MerkleRootHash)
	fmt.Println("Size: ", response.Size)

	return nil
}

func GetStorageAccessToken(ctx *cli.Context) error {
	conf := config.New(ctx)
	endpoint, err := os.ReadFile(filepath.Join(conf.Global.DataDir, "client_jsonrpc_endpoint.txt"))
	if err != nil {
		return fmt.Errorf("failed to read client endpoint file: %w", err)
	}

	ffgclient, err := client.New(string(endpoint), http.DefaultClient)
	if err != nil {
		return fmt.Errorf("failed to setup client: %w", err)
	}

	adminToken := ctx.Args().First()
	if adminToken == "" {
		return errors.New("admin token is empty")
	}

	jwtToken, err := ffgclient.GetStorageAccessToken(ctx.Context, adminToken)
	if err != nil {
		return fmt.Errorf("failed to get storage token: %w", err)
	}

	fmt.Println("Access token: ", jwtToken)

	return nil
}

// SetEndpoint sets the endpoint to be used across the client commands.
func SetEndpoint(ctx *cli.Context) error {
	conf := config.New(ctx)

	endPoint := ctx.Args().First()
	if endPoint == "" {
		return errors.New("endpoint is empty")
	}

	_, err := common.WriteToFile([]byte(endPoint), filepath.Join(conf.Global.DataDir, "client_jsonrpc_endpoint.txt"))
	if err != nil {
		return fmt.Errorf("failed to write endpoint to file")
	}
	return nil
}

// SendTransaction sends a transaction.
func SendTransaction(ctx *cli.Context) error {
	conf := config.New(ctx)
	endpoint, err := os.ReadFile(filepath.Join(conf.Global.DataDir, "client_jsonrpc_endpoint.txt"))
	if err != nil {
		return fmt.Errorf("failed to read client endpoint file: %w", err)
	}

	ffgclient, err := client.New(string(endpoint), http.DefaultClient)
	if err != nil {
		return fmt.Errorf("failed to setup client: %w", err)
	}

	accessToken := ctx.Args().First()
	if accessToken == "" {
		return errors.New("access token is empty")
	}

	nounce := ctx.Args().Get(1)
	if nounce == "" {
		return errors.New("nounce is empty")
	}

	data := ctx.Args().Get(2)
	if data == "" {
		return errors.New("data is empty")
	}

	from := ctx.Args().Get(3)
	if from == "" {
		return errors.New("from is empty")
	}

	to := ctx.Args().Get(4)
	if to == "" {
		return errors.New("to is empty")
	}

	txValue := ctx.Args().Get(5)
	if txValue == "" {
		return errors.New("transaction value is empty")
	}

	txFees := ctx.Args().Get(6)
	if txFees == "" {
		return errors.New("transaction fees is empty")
	}

	response, err := ffgclient.SendTransaction(ctx.Context, accessToken, client.SendTransaction{
		Nounce:          nounce,
		Data:            data,
		From:            from,
		To:              to,
		Value:           txValue,
		TransactionFees: txFees,
	})
	if err != nil {
		return fmt.Errorf("failed to send transaction: %w", err)
	}

	fmt.Println("Transaction sent with hash: ", response.Transaction.Hash)

	return nil
}

func UnlockAddress(ctx *cli.Context) error {
	conf := config.New(ctx)
	endpoint, err := os.ReadFile(filepath.Join(conf.Global.DataDir, "client_jsonrpc_endpoint.txt"))
	if err != nil {
		return fmt.Errorf("failed to read client endpoint file: %w", err)
	}

	ffgclient, err := client.New(string(endpoint), http.DefaultClient)
	if err != nil {
		return fmt.Errorf("failed to setup client: %w", err)
	}

	address := ctx.Args().First()
	if address == "" {
		return errors.New("address is empty")
	}

	passphrase := ctx.Args().Get(1)
	if passphrase == "" {
		return errors.New("passphrase is empty")
	}

	jwt, err := ffgclient.UnlockAddress(ctx.Context, "", passphrase)
	if err != nil {
		return fmt.Errorf("failed to unlock address: %w", err)
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
	if address == "" {
		return errors.New("address is empty")
	}
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
	if dataQueryRequestHash == "" {
		return errors.New("data query request hash is empty")
	}

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

	if len(fileHashes) == 0 {
		return errors.New("file hashes in the request is empty")
	}

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

	if dataQueryRequestHash == "" {
		return errors.New("data query request hash is empty")
	}

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
	contractHashes := strings.Split(downloadContractHashes, ",")
	if len(contractHashes) == 0 {
		return errors.New("contract hashes are empty")
	}

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
	if downloadContractHash == "" {
		return errors.New("contract hash is empty")
	}

	fileHash := ctx.Args().Get(1)
	if fileHash == "" {
		return errors.New("file hash is empty")
	}

	downloadContract, err := ffgclient.GetDownloadContract(ctx.Context, downloadContractHash)
	if err != nil {
		return fmt.Errorf("failed to get download contract: %w", err)
	}

	sizeOfFile := uint64(0)
	for i, v := range downloadContract.Contract.FileHashesNeeded {
		if v == fileHash {
			sizeOfFile = downloadContract.Contract.FileHashesNeededSizes[i]
		}
	}

	stats, err := ffgclient.DownloadFile(ctx.Context, downloadContractHash, fileHash, false)
	if err != nil {
		return fmt.Errorf("failed to start downloading file: %w", err)
	}

	fmt.Println("Download stats: ", stats)
	bar := progressbar.NewOptions64(int64(sizeOfFile),
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
			break
		}
		_ = bar.Set(int(prog.BytesTransfered))
		bytesTransfered = prog.BytesTransfered
		time.Sleep(5 * time.Millisecond)
	}

	return nil
}

func SendFileMerkleTreeNodesToVerifier(ctx *cli.Context) error {
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
	if downloadContractHash == "" {
		return errors.New("contract hash is empty")
	}
	fileHash := ctx.Args().Get(1)
	if fileHash == "" {
		return errors.New("file hash is empty")
	}

	ok, err := ffgclient.SendFileMerkleTreeNodesToVerifier(ctx.Context, downloadContractHash, fileHash)
	if err != nil || !ok {
		return fmt.Errorf("failed to send merkle tree nodes to verifier: %w", err)
	}

	fmt.Println("successfully sent the file's signature")
	return nil
}

func DecryptAllFiles(ctx *cli.Context) error {
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
	if downloadContractHash == "" {
		return fmt.Errorf("contract hash is empty")
	}

	fileHashes := ctx.Args().Get(1)
	if fileHashes == "" {
		return fmt.Errorf("files hashes are empty")
	}
	fileHashesAll := strings.Split(fileHashes, ",")

	fileMerkleHashes := ctx.Args().Get(2)
	if fileMerkleHashes == "" {
		return fmt.Errorf("files merkle root hashes are empty")
	}
	fileMerkleRootHashesAll := strings.Split(fileMerkleHashes, ",")

	restoreFiles := ctx.Args().Get(3)
	if restoreFiles == "" {
		return fmt.Errorf("restoring file paths are empty")
	}

	restoredFilesPaths := strings.Split(restoreFiles, ",")
	restoredPaths, err := ffgclient.RequestEncryptionDataFromVerifierAndDecrypt(ctx.Context, downloadContractHash, fileHashesAll, fileMerkleRootHashesAll, restoredFilesPaths)
	if err != nil {
		return fmt.Errorf("failed to request encryption data from verifier: %w", err)
	}

	for _, v := range restoredPaths {
		fmt.Println("File decrypted: ", v)
	}

	return nil
}
