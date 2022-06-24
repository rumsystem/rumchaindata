package data

import (
	"bytes"
	"errors"
	"time"

	guuid "github.com/google/uuid"
	p2pcrypto "github.com/libp2p/go-libp2p-core/crypto"
	localcrypto "github.com/rumsystem/keystore/pkg/crypto"
	//"github.com/rumsystem/quorum/internal/pkg/nodectx"
	quorumpb "github.com/rumsystem/rumchaindata/pkg/pb"
	"google.golang.org/protobuf/proto"
)

func CreateBlock(oldBlock *quorumpb.Block, trxs []*quorumpb.Trx, groupPublicKey []byte, keystore localcrypto.Keystore, keyalias string, opts ...string) (*quorumpb.Block, error) {
	var newBlock quorumpb.Block
	blockId := guuid.New()

	//deep copy trx by the protobuf. quorumpb.Trx is a protobuf defined struct.

	newBlock.BlockId = blockId.String()
	newBlock.GroupId = oldBlock.GroupId
	newBlock.PrevBlockId = oldBlock.BlockId
	newBlock.PreviousHash = oldBlock.Hash
	for _, trx := range trxs {
		trxclone := &quorumpb.Trx{}
		clonedtrxbuff, err := proto.Marshal(trx)

		err = proto.Unmarshal(clonedtrxbuff, trxclone)
		if err != nil {
			return nil, err
		}
		newBlock.Trxs = append(newBlock.Trxs, trxclone)
	}
	newBlock.ProducerPubKey = p2pcrypto.ConfigEncodeKey(groupPublicKey)
	newBlock.TimeStamp = time.Now().UnixNano()

	bbytes, err := proto.Marshal(&newBlock)

	if err != nil {
		return nil, err
	}

	hash := localcrypto.Hash(bbytes)
	newBlock.Hash = hash

	var signature []byte
	if keyalias == "" {
		signature, err = keystore.SignByKeyName(newBlock.GroupId, hash, opts...)
	} else {
		signature, err = keystore.SignByKeyAlias(keyalias, hash, opts...)
	}

	if err != nil {
		return nil, err
	}

	if len(signature) == 0 {
		return nil, errors.New("create signature on genesisblock failed")
	}
	newBlock.Signature = signature

	return &newBlock, nil
}

func CreateGenesisBlock(groupId string, groupPublicKey p2pcrypto.PubKey, keystore localcrypto.Keystore, keyalias string) (*quorumpb.Block, error) {
	encodedgroupPubkey, err := p2pcrypto.MarshalPublicKey(groupPublicKey)
	if err != nil {
		return nil, err
	}
	var genesisBlock quorumpb.Block
	genesisBlock.BlockId = guuid.New().String()
	genesisBlock.GroupId = groupId
	genesisBlock.PrevBlockId = ""
	genesisBlock.PreviousHash = nil
	genesisBlock.TimeStamp = time.Now().UnixNano()

	genesisBlock.ProducerPubKey = p2pcrypto.ConfigEncodeKey(encodedgroupPubkey)
	genesisBlock.Trxs = nil

	bbytes, err := proto.Marshal(&genesisBlock)
	if err != nil {
		return nil, err
	}

	hash := localcrypto.Hash(bbytes)
	genesisBlock.Hash = hash

	var signature []byte
	if keyalias == "" {
		signature, err = keystore.SignByKeyName(genesisBlock.GroupId, hash)
	} else {
		signature, err = keystore.SignByKeyAlias(keyalias, hash)
	}
	if err != nil {
		return nil, err
	}
	if len(signature) == 0 {
		return nil, errors.New("create signature on genesisblock failed")
	}
	genesisBlock.Signature = signature

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
	blockWithoutHash.Signature = nil

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
	//create pubkey
	serializedpub, err := p2pcrypto.ConfigDecodeKey(block.ProducerPubKey)
	if err != nil {
		return false, err
	}

	pubkey, err := p2pcrypto.UnmarshalPublicKey(serializedpub)
	if err != nil {
		return false, err
	}
	return pubkey.Verify(hash, block.Signature)
}

func IsBlockValid(newBlock, oldBlock *quorumpb.Block) (bool, error) {
	hash, err := BlockHash(newBlock)
	if err != nil {
		return false, err
	}

	if res := bytes.Compare(hash, newBlock.Hash); res != 0 {
		return false, errors.New("Hash for new block is invalid")
	}

	if res := bytes.Compare(newBlock.PreviousHash, oldBlock.Hash); res != 0 {
		return false, errors.New("PreviousHash mismatch")
	}

	if newBlock.PrevBlockId != oldBlock.BlockId {
		return false, errors.New("Previous BlockId mismatch")
	}

	//create pubkey
	serializedpub, err := p2pcrypto.ConfigDecodeKey(newBlock.ProducerPubKey)
	if err != nil {
		return false, err
	}

	pubkey, err := p2pcrypto.UnmarshalPublicKey(serializedpub)
	if err != nil {
		return false, err
	}

	verify, err := pubkey.Verify(newBlock.Hash, newBlock.Signature)
	return verify, err
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
