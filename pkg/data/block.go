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

// Each block has 2 hashs, trxHash and bookkeepingHash
// trxHash includes the following items
// - Epoch
// - GroupId
// - PrevHash
// - all trxs
// since each round of acs between different producers will make an "agreement" which trxs to be included in this round of epoch
// hash those info will guarantee the consensused info are correct.
// After add
// - withness info
// - bookkeeping pubkey
// - timestamp
// get hash again, this is bookkeepingHash
// bookkeeping node will sigh this hash with to guarantee everything in this block is bookkeeping correctly.

func CreateBlockByEthKey(oldBlock *quorumpb.Block, epoch int64, trxs []*quorumpb.Trx, groupPublicKey string, withnesses []*quorumpb.Witnesses, keystore localcrypto.Keystore, keyalias string, opts ...string) (*quorumpb.Block, error) {
	var newBlock quorumpb.Block

	newBlock.Epoch = epoch
	newBlock.GroupId = oldBlock.GroupId
	newBlock.PrevTrxHash = oldBlock.TrxHash
	for _, trx := range trxs {
		trxclone := &quorumpb.Trx{}
		clonedtrxbuff, err := proto.Marshal(trx)

		err = proto.Unmarshal(clonedtrxbuff, trxclone)
		if err != nil {
			return nil, err
		}
		newBlock.Trxs = append(newBlock.Trxs, trxclone)
	}

	tbytes, err := proto.Marshal(&newBlock)

	if err != nil {
		return nil, err
	}

	trxHash := localcrypto.Hash(tbytes)
	newBlock.TrxHash = trxHash

	//add withnesses and calcualte hash again
	newBlock.Witesses = withnesses
	newBlock.TimeStamp = time.Now().UnixNano()
	newBlock.BookkeepingPubkey = groupPublicKey

	bbytes, err := proto.Marshal(&newBlock)
	bookkeepingHash := localcrypto.Hash(bbytes)

	var signature []byte
	if keyalias == "" {
		signature, err = keystore.EthSignByKeyName(newBlock.GroupId, bookkeepingHash, opts...)
	} else {
		signature, err = keystore.EthSignByKeyAlias(keyalias, bookkeepingHash, opts...)
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
	genesisBlock := &quorumpb.Block{}
	genesisBlock.Epoch = 0
	genesisBlock.GroupId = groupId
	genesisBlock.PrevTrxHash = nil
	genesisBlock.Trxs = nil

	tbytes, err := proto.Marshal(genesisBlock)
	if err != nil {
		return nil, err
	}

	trxHash := localcrypto.Hash(tbytes)
	genesisBlock.TrxHash = trxHash

	genesisBlock.Witesses = nil
	genesisBlock.TimeStamp = time.Now().UnixNano()
	genesisBlock.BookkeepingPubkey = groupPublicKey

	bbytes, err := proto.Marshal(genesisBlock)
	bookkeepingHash := localcrypto.Hash(bbytes)

	var signature []byte
	if keyalias == "" {
		signature, err = keystore.EthSignByKeyName(genesisBlock.GroupId, bookkeepingHash)
	} else {
		signature, err = keystore.EthSignByKeyAlias(keyalias, bookkeepingHash)
	}
	if err != nil {
		return nil, err
	}
	if len(signature) == 0 {
		return nil, errors.New("create signature on genesisblock failed")
	}
	genesisBlock.BookkeepingSignature = signature

	return genesisBlock, nil
}

func BlockBookKeepingHash(block *quorumpb.Block) ([]byte, error) {
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

	blockWithoutHash.BookkeepingHash = nil
	blockWithoutHash.BookkeepingSignature = nil

	bbytes, err := proto.Marshal(blockWithoutHash)
	if err != nil {
		return nil, err
	}

	hash := localcrypto.Hash(bbytes)
	return hash, nil
}

func BlockTrxHash(block *quorumpb.Block) ([]byte, error) {
	blockWithoutHash := &quorumpb.Block{
		GroupId:     block.GroupId,
		Epoch:       block.Epoch,
		PrevTrxHash: block.PrevTrxHash,
		Trxs:        block.Trxs,
	}

	tbytes, err := proto.Marshal(blockWithoutHash)
	if err != nil {
		return nil, err
	}
	hash := localcrypto.Hash(tbytes)
	return hash, nil
}

func VerifyBookkeepingSign(block *quorumpb.Block) (bool, error) {
	bookkeepingHash, err := BlockBookKeepingHash(block)
	if err != nil {
		return false, err
	}

	bytespubkey, err := base64.RawURLEncoding.DecodeString(block.BookkeepingPubkey)
	if err == nil { //try eth key
		ethpubkey, err := ethcrypto.DecompressPubkey(bytespubkey)
		if err == nil {
			ks := localcrypto.GetKeystore()
			r := ks.EthVerifySign(bookkeepingHash, block.GetBookkeepingSignature(), ethpubkey)
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
	return pubkey.Verify(bookkeepingHash, block.BookkeepingSignature)
}

func IsBlockValid(newBlock, oldBlock *quorumpb.Block) (bool, error) {

	trxHash, err := BlockTrxHash(newBlock)
	if err != nil {
		return false, err
	}

	if res := bytes.Compare(trxHash, newBlock.TrxHash); res != 0 {
		return false, errors.New("TrxHash for new block is invalid")
	}

	if res := bytes.Compare(newBlock.PrevTrxHash, oldBlock.TrxHash); res != 0 {
		return false, errors.New("PreviousHash mismatch")
	}

	if newBlock.Epoch != oldBlock.Epoch+1 {
		return false, errors.New("Previous epoch mismatch")
	}

	return VerifyBookkeepingSign(newBlock)
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
