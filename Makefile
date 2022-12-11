build:
	go build -o cmd/filefilego/filefilego cmd/filefilego/main.go
lint:
	golangci-lint run --disable-all -E govet -E revive -E gofumpt -E gosec -E unparam -E goconst -E prealloc -E stylecheck -E unconvert -E errcheck -E ineffassign -E unused -E tparallel -E whitespace -E staticcheck -E gosimple -E gocritic
run:
	go run cmd/filefilego/main.go
test:
	go test ./... -race -count=1 -failfast
coverage:
	go test ./... -race -count=1 -failfast -coverprofile=coverage.out && go tool cover -html=coverage.out && rm coverage.out