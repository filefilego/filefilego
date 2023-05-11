build:
	go build -o cmd/filefilego/filefilego cmd/filefilego/main.go
lint:
	golangci-lint run --disable-all -E misspell -E govet -E revive -E gofumpt -E gosec -E unparam -E goconst -E prealloc -E stylecheck -E unconvert -E errcheck -E ineffassign -E unused -E tparallel -E whitespace -E staticcheck -E gosimple -E gocritic
run:
	go run cmd/filefilego/main.go --storage_token="admintoken"
unit:
	go test ./... -race -count=1 -failfast
coverage:
	go test ./... -race -count=1 -failfast -coverprofile=coverage.out && go tool cover -html=coverage.out && rm coverage.out
genproto:
	# protoc --go_out=transaction transaction/transaction.proto
	# protoc --proto_path=. --go_out=block block/block.proto transaction/transaction.proto
	# protoc --go_out=blockchain blockchain/types.proto
	protoc --proto_path=. --go_out=node node/protocols/messages/messages.proto block/block.proto transaction/transaction.proto