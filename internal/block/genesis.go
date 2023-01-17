package block

import (
	"errors"
	"fmt"
	"os"
)

// GetGenesisBlock returns the genesis block.
func GetGenesisBlock(filePath string) (*Block, error) {
	genesisData, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read genesis block file: %w", err)
	}

	genesisProto, err := UnmarshalProtoBlock(genesisData)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal genesis block file: %w", err)
	}

	genesisBlock := ProtoBlockToBlock(genesisProto)
	ok, err := genesisBlock.Validate()
	if err != nil {
		return nil, fmt.Errorf("failed to validate genesis block: %w", err)
	}

	if !ok {
		return nil, errors.New("genesis block validation is false")
	}

	return &genesisBlock, nil
}
