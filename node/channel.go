package node

import (
	"math/big"

	proto "google.golang.org/protobuf/proto"

	"github.com/filefilego/filefilego/common/hexutil"
	log "github.com/sirupsen/logrus"
)

// IsValidChannelPayload checks if a valid channel payload
func (bc *Blockchain) IsValidChannelPayload(t Transaction, currentBalance *big.Int) bool {
	ap := TransactionDataPayload{}
	bts, _ := proto.Marshal(&ap)
	originHex := hexutil.Encode(bts) // need this to see if the ChanActionPayload is the same after unmarshalling
	if err := proto.Unmarshal(t.Data, &ap); err != nil {
		log.Warn("Invalid transaction payload of type ChanActionPayload. Ignore as it's possible to store any arbitrary data", err)
		return true
	}

	bts, _ = proto.Marshal(&ap)
	afterUnmarshalHex := hexutil.Encode(bts)

	// ALL channel operations must send the tx to valid verifier addrs
	if originHex != afterUnmarshalHex {
		destinationAddrIsVerifier := false
		for _, v := range bc.Node.GetBlockchainSettings().Verifiers {
			if v.Address == t.To {
				destinationAddrIsVerifier = true
				break
			}
		}

		if !destinationAddrIsVerifier {
			log.Warn("Trying to register a namespace with incorrect destination address")
			return false
		}
	}

	txVal, err1 := hexutil.DecodeBig(t.Value)
	if err1 != nil {
		log.Error(err1)
		return false
	}

	//  if registering a channel: check for enough balance and
	if originHex != afterUnmarshalHex && ap.Type == TransactionDataPayloadType_CREATE_NODE {

		chEnvs := ChanNodeEnvelop{}
		err := proto.Unmarshal(ap.Payload, &chEnvs)
		if err != nil {
			return false
		}
		var regFee, _ = new(big.Int).SetString(bc.Node.GetBlockchainSettings().NamespaceRegistrationFee, 10)
		var totalBalanceRequired, _ = new(big.Int).SetString("0", 10)
		for _, chaNode := range chEnvs.Nodes {
			// if channel, MUST have no parent hash, and enough balance

			if chaNode.NodeType == ChanNodeType_CHANNEL {
				if chaNode.ParentHash != "" {
					return false
				}
				totalBalanceRequired = totalBalanceRequired.Add(totalBalanceRequired, regFee)
			}
		}

		if currentBalance.Cmp(totalBalanceRequired) < 0 {

			return false
		}

		if txVal.Cmp(totalBalanceRequired) < 0 {

			return false
		}

	}

	return true
}
