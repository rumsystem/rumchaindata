package data

import (
	"bytes"
	"encoding/base64"
	"errors"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	p2pcrypto "github.com/libp2p/go-libp2p-core/crypto"
	localcrypto "github.com/rumsystem/keystore/pkg/crypto"
	quorumpb "github.com/rumsystem/rumchaindata/pkg/pb"
	"google.golang.org/protobuf/proto"

	//"strings"
	"time"
)

//deep copy trx by the protobuf. quorumpb.Trx is a protobuf defined struct.
// block hash include the following items
// - Epoch
// - GroupId
// - PrevHash
// - all trxs
// - after add withness info, get hash again, sigh this hash with bookkeeping private key

func CreateBlockByEthKey(oldBlock *quorumpb.Block, epoch int64, trxs []*quorumpb.Trx, groupPublicKey string, withnesses []*quorumpb.Witnesses, keystore localcrypto.Keystore, keyalias string, opts ...string) (*quorumpb.Block, error) {
	var newBlock quorumpb.Block

	newBlock.Epoch = epoch
	newBlock.GroupId = oldBlock.GroupId
	newBlock.PrevHash = oldBlock.Hash
	for _, trx := range trxs {
		trxclone := &quorumpb.Trx{}
		clonedtrxbuff, err := proto.Marshal(trx)

		err = proto.Unmarshal(clonedtrxbuff, trxclone)
		if err != nil {
			return nil, err
		}
		newBlock.Trxs = append(newBlock.Trxs, trxclone)
	}

	bbytes, err := proto.Marshal(&newBlock)

	if err != nil {
		return nil, err
	}

	hash := localcrypto.Hash(bbytes)
	newBlock.Hash = hash

	//add withnesses and calcualte hash again
	newBlock.Witesses = withnesses
	newBlock.TimeStamp = time.Now().UnixNano()
	newBlock.BookkeepingPubkey = groupPublicKey

	witnessB, err := proto.Marshal(&newBlock)
	var signature []byte
	if keyalias == "" {
		signature, err = keystore.EthSignByKeyName(newBlock.GroupId, witnessB, opts...)
	} else {
		signature, err = keystore.EthSignByKeyAlias(keyalias, witnessB, opts...)
	}

	if err != nil {
		return nil, err
	}

	if len(signature) == 0 {
		return nil, errors.New("create signature failed")
	}
	newBlock.BookkeepingSignature = signature

	return &newBlock, nil
}

func CreateGenesisBlockByEthKey(groupId string, groupPublicKey string, keystore localcrypto.Keystore, keyalias string) (*quorumpb.Block, error) {
	var genesisBlock quorumpb.Block
	genesisBlock.Epoch = 0
	genesisBlock.GroupId = groupId
	genesisBlock.PrevHash = nil
	genesisBlock.TimeStamp = time.Now().UnixNano()
	genesisBlock.BookkeepingPubkey = groupPublicKey
	genesisBlock.Trxs = nil
	withnesses := &quorumpb.Witnesses{}
	genesisBlock.Witesses = append(genesisBlock.Witesses, withnesses)

	hash, err := BlockHash(&genesisBlock)
	if err != nil {
		return nil, err
	}
	genesisBlock.Hash = hash

	var signature []byte
	if keyalias == "" {
		signature, err = keystore.EthSignByKeyName(genesisBlock.GroupId, hash)
	} else {
		signature, err = keystore.EthSignByKeyAlias(keyalias, hash)
	}
	if err != nil {
		return nil, err
	}
	if len(signature) == 0 {
		return nil, errors.New("create signature on genesisblock failed")
	}
	genesisBlock.BookkeepingSignature = signature

	return &genesisBlock, nil
}

func BlockHash(block *quorumpb.Block) ([]byte, error) {
	clonedblockbuff, err := proto.Marshal(block)
	if err != nil {
		return nil, err
	}
	var blockWithoutHash *quorumpb.Block
	blockWithoutHash = &quorumpb.Block{}

	err = proto.Unmarshal(clonedblockbuff, blockWithoutHash)
	if err != nil {
		return nil, err
	}
	blockWithoutHash.Hash = nil
	blockWithoutHash.BookkeepingSignature = nil

	bbytes, err := proto.Marshal(blockWithoutHash)
	if err != nil {
		return nil, err
	}

	hash := localcrypto.Hash(bbytes)
	return hash, nil
}

func VerifyBlockSign(block *quorumpb.Block) (bool, error) {
	hash, err := BlockHash(block)
	if err != nil {
		return false, err
	}
	bytespubkey, err := base64.RawURLEncoding.DecodeString(block.BookkeepingPubkey)
	if err == nil { //try eth key
		ethpubkey, err := ethcrypto.DecompressPubkey(bytespubkey)
		if err == nil {
			ks := localcrypto.GetKeystore()
			r := ks.EthVerifySign(hash, block.GetBookkeepingSignature(), ethpubkey)
			return r, nil
		}
	}

	//libp2p key for backward campatibility
	serializedpub, err := p2pcrypto.ConfigDecodeKey(block.BookkeepingPubkey)
	if err != nil {
		return false, err
	}

	pubkey, err := p2pcrypto.UnmarshalPublicKey(serializedpub)
	if err != nil {
		return false, err
	}
	return pubkey.Verify(hash, block.BookkeepingSignature)
}

func IsBlockValid(newBlock, oldBlock *quorumpb.Block) (bool, error) {
	hash, err := BlockHash(newBlock)
	if err != nil {
		return false, err
	}

	if res := bytes.Compare(hash, newBlock.Hash); res != 0 {
		return false, errors.New("Hash for new block is invalid")
	}

	if res := bytes.Compare(newBlock.Hash, oldBlock.Hash); res != 0 {
		return false, errors.New("PreviousHash mismatch")
	}

	if newBlock.Epoch != oldBlock.Epoch+1 {
		return false, errors.New("Previous epoch mismatch")
	}

	// check withness
	// 1. calculate hash for []trxs in block, compare with hash in withness
	// 2. check withness signature by using withness pubkey

	return VerifyBlockSign(newBlock)
}

//get all trx from the block list
func GetAllTrxs(blocks []*quorumpb.Block) ([]*quorumpb.Trx, error) {
	var trxs []*quorumpb.Trx
	for _, block := range blocks {
		for _, trx := range block.Trxs {
			trxs = append(trxs, trx)
		}
	}
	return trxs, nil
}
