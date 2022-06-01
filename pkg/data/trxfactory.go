package data

import (
	"encoding/binary"
	"errors"
	quorumpb "github.com/rumsystem/rumchaindata/pkg/pb"
	"google.golang.org/protobuf/proto"
)

type TrxFactory struct {
	nodename   string
	groupId    string
	groupItem  *quorumpb.GroupItem
	chainNonce ChainNonce
	version    string
}

type ChainNonce interface {
	GetNextNouce(groupId string, prefix ...string) (nonce uint64, err error)
}

func (factory *TrxFactory) Init(version string, groupItem *quorumpb.GroupItem, nodename string, chainnonce ChainNonce) {
	factory.groupItem = groupItem
	factory.groupId = groupItem.GroupId
	factory.nodename = nodename
	factory.chainNonce = chainnonce
	factory.version = version
}

func (factory *TrxFactory) CreateTrx(msgType quorumpb.TrxType, data []byte, encryptto ...[]string) (*quorumpb.Trx, error) {
	nonce, err := factory.chainNonce.GetNextNouce(factory.groupItem.GroupId, factory.nodename)
	if err != nil {
		return nil, err
	}
	return CreateTrx(factory.nodename, factory.version, factory.groupItem, msgType, int64(nonce), data, encryptto...)
}

func (factory *TrxFactory) CreateTrxWithKeyAlias(keyalias string, msgType quorumpb.TrxType, data []byte, encryptto ...[]string) (*quorumpb.Trx, error) {
	nonce, err := factory.chainNonce.GetNextNouce(factory.groupItem.GroupId, factory.nodename)
	if err != nil {
		return nil, err
	}
	return CreateTrxWithKeyAlias(factory.nodename, keyalias, factory.version, factory.groupItem, msgType, int64(nonce), data, encryptto...)
}

func (factory *TrxFactory) GetUpdAppConfigTrx(item *quorumpb.AppConfigItem) (*quorumpb.Trx, error) {
	encodedcontent, err := proto.Marshal(item)
	if err != nil {
		return nil, err
	}

	return factory.CreateTrx(quorumpb.TrxType_APP_CONFIG, encodedcontent)
}

func (factory *TrxFactory) GetChainConfigTrx(item *quorumpb.ChainConfigItem) (*quorumpb.Trx, error) {
	encodedcontent, err := proto.Marshal(item)
	if err != nil {
		return nil, err
	}

	return factory.CreateTrx(quorumpb.TrxType_CHAIN_CONFIG, encodedcontent)
}

func (factory *TrxFactory) GetRegProducerTrx(item *quorumpb.ProducerItem) (*quorumpb.Trx, error) {
	encodedcontent, err := proto.Marshal(item)
	if err != nil {
		return nil, err
	}
	return factory.CreateTrx(quorumpb.TrxType_PRODUCER, encodedcontent)
}

func (factory *TrxFactory) GetRegUserTrx(item *quorumpb.UserItem) (*quorumpb.Trx, error) {
	encodedcontent, err := proto.Marshal(item)
	if err != nil {
		return nil, err
	}
	return factory.CreateTrx(quorumpb.TrxType_USER, encodedcontent)
}

func (factory *TrxFactory) GetAnnounceTrx(item *quorumpb.AnnounceItem) (*quorumpb.Trx, error) {
	encodedcontent, err := proto.Marshal(item)
	if err != nil {
		return nil, err
	}

	return factory.CreateTrx(quorumpb.TrxType_ANNOUNCE, encodedcontent)
}

func (factory *TrxFactory) GetUpdSchemaTrx(item *quorumpb.SchemaItem) (*quorumpb.Trx, error) {
	encodedcontent, err := proto.Marshal(item)
	if err != nil {
		return nil, err
	}

	return factory.CreateTrx(quorumpb.TrxType_SCHEMA, encodedcontent)
}

func (factory *TrxFactory) GetReqBlockRespTrx(requester string, block *quorumpb.Block, result quorumpb.ReqBlkResult) (*quorumpb.Trx, error) {
	var reqBlockRespItem quorumpb.ReqBlockResp
	reqBlockRespItem.Result = result
	reqBlockRespItem.ProviderPubkey = factory.groupItem.UserSignPubkey
	reqBlockRespItem.RequesterPubkey = requester
	reqBlockRespItem.GroupId = block.GroupId
	reqBlockRespItem.BlockId = block.BlockId

	pbBytesBlock, err := proto.Marshal(block)
	if err != nil {
		return nil, err
	}
	reqBlockRespItem.Block = pbBytesBlock

	bItemBytes, err := proto.Marshal(&reqBlockRespItem)
	if err != nil {
		return nil, err
	}

	//send ask next block trx out
	return CreateTrx(factory.nodename, factory.version, factory.groupItem, quorumpb.TrxType_REQ_BLOCK_RESP, int64(0), bItemBytes)
}

func (factory *TrxFactory) GetReqBlockForwardTrx(block *quorumpb.Block) (*quorumpb.Trx, error) {
	var reqBlockItem quorumpb.ReqBlock
	reqBlockItem.BlockId = block.BlockId
	reqBlockItem.GroupId = block.GroupId
	reqBlockItem.UserId = factory.groupItem.UserSignPubkey

	bItemBytes, err := proto.Marshal(&reqBlockItem)
	if err != nil {
		return nil, err
	}

	return CreateTrx(factory.nodename, factory.version, factory.groupItem, quorumpb.TrxType_REQ_BLOCK_FORWARD, int64(0), bItemBytes)
}

func (factory *TrxFactory) GetReqBlockBackwardTrx(block *quorumpb.Block) (*quorumpb.Trx, error) {
	var reqBlockItem quorumpb.ReqBlock
	reqBlockItem.BlockId = block.BlockId
	reqBlockItem.GroupId = block.GroupId
	reqBlockItem.UserId = factory.groupItem.UserSignPubkey

	bItemBytes, err := proto.Marshal(&reqBlockItem)
	if err != nil {
		return nil, err
	}

	return CreateTrx(factory.nodename, factory.version, factory.groupItem, quorumpb.TrxType_REQ_BLOCK_BACKWARD, int64(0), bItemBytes)
}

func (factory *TrxFactory) GetBlockProducedTrx(blk *quorumpb.Block) (*quorumpb.Trx, error) {
	encodedcontent, err := proto.Marshal(blk)
	if err != nil {
		return nil, err
	}
	return CreateTrx(factory.nodename, factory.version, factory.groupItem, quorumpb.TrxType_BLOCK_PRODUCED, int64(0), encodedcontent)
}

func (factory *TrxFactory) GetPostAnyTrx(content proto.Message, encryptto ...[]string) (*quorumpb.Trx, error) {
	encodedcontent, err := quorumpb.ContentToBytes(content)
	if err != nil {
		return nil, err
	}

	if binary.Size(encodedcontent) > OBJECT_SIZE_LIMIT {
		err := errors.New("Content size over 200Kb")
		return nil, err
	}

	return factory.CreateTrx(quorumpb.TrxType_POST, encodedcontent, encryptto...)
}

func (factory *TrxFactory) GetPostAnyTrxWithKeyAlias(keyalias string, content proto.Message, encryptto ...[]string) (*quorumpb.Trx, error) {
	encodedcontent, err := quorumpb.ContentToBytes(content)
	if err != nil {
		return nil, err
	}

	if binary.Size(encodedcontent) > OBJECT_SIZE_LIMIT {
		err := errors.New("Content size over 200Kb")
		return nil, err
	}

	return factory.CreateTrxWithKeyAlias(keyalias, quorumpb.TrxType_POST, encodedcontent, encryptto...)
}
