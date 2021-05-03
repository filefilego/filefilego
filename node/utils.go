package node

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"

	"github.com/filefilego/filefilego/crypto"
	log "github.com/sirupsen/logrus"
	proto "google.golang.org/protobuf/proto"
)

// GetHash returns a hash of the contract
func (c *DataContract) GetHash() []byte {
	data := bytes.Join(
		[][]byte{
			c.RequesterNodePubKey,
			c.VerifierPubKey,
			c.HostResponse.PubKey,
			c.HostResponse.Signature,
			bytes.Join(c.HostResponse.Nodes, []byte{}),
		},
		[]byte{},
	)
	// data, _ := proto.Marshal(c)
	return crypto.Sha256HashHexBytes(data)
}

// GetTransactionID gets a hash of a transaction
func GetTransactionID(tx *Transaction) []byte {
	data := bytes.Join(
		[][]byte{
			[]byte(tx.PubKey),
			[]byte(tx.Nounce),
			tx.Data,
			[]byte(tx.From),
			[]byte(tx.To),
			[]byte(tx.Value),
			[]byte(tx.TransactionFees),
			BlockchainChainID,
		},
		[]byte{},
	)
	hash := sha256.Sum256(data)
	bts := hash[:]
	return bts
}

// SerializeTransaction serialized  transaction
func SerializeTransaction(tx Transaction) []byte {
	blkBts, err := proto.Marshal(&tx)
	if err != nil {
		log.Println(err)
	}
	return blkBts
}

// UnserializeTransaction converts a byte array to a transaction
func UnserializeTransaction(data []byte) Transaction {
	tx := Transaction{}
	if err := proto.Unmarshal(data, &tx); err != nil {
		log.Warn("error while unmarshalling data from stream: ", err)
	}
	return tx
}

// IntToHex converts an int64 to a byte array
func IntToHex(num int64) ([]byte, error) {
	buff := new(bytes.Buffer)
	err := binary.Write(buff, binary.BigEndian, num)
	if err != nil {
		return buff.Bytes(), err
	}

	return buff.Bytes(), nil
}
