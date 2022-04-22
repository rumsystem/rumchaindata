package data

import (
	"encoding/hex"
	"fmt"
	guuid "github.com/google/uuid"
	p2pcrypto "github.com/libp2p/go-libp2p-core/crypto"
	localcrypto "github.com/rumsystem/keystore/pkg/crypto"
	quorumpb "github.com/rumsystem/rumchaindata/pkg/pb"
	"google.golang.org/protobuf/proto"
	"time"
)

const (
	Hours = 0
	Mins  = 0
	Sec   = 30
)

func CreateTrxWithoutSign(nodename string, version string, groupItem *quorumpb.GroupItem, msgType quorumpb.TrxType, nonce int64, data []byte, encryptto ...[]string) (*quorumpb.Trx, []byte, error) {
	var trx quorumpb.Trx

	trxId := guuid.New()
	trx.TrxId = trxId.String()
	trx.Type = msgType
	trx.GroupId = groupItem.GroupId
	trx.SenderPubkey = groupItem.UserSignPubkey
	trx.Nonce = nonce

	var encryptdData []byte
	if msgType == quorumpb.TrxType_POST && groupItem.EncryptType == quorumpb.GroupEncryptType_PRIVATE {
		//for post, private group, encrypted by age for all announced group users
		if len(encryptto) == 1 {
			var err error
			ks := localcrypto.GetKeystore()
			if len(encryptto[0]) == 0 {
				return &trx, []byte(""), fmt.Errorf("must have encrypt pubkeys for private group %s", groupItem.GroupId)
			}
			encryptdData, err = ks.EncryptTo(encryptto[0], data)
			if err != nil {
				return &trx, []byte(""), err
			}

		} else {
			return &trx, []byte(""), fmt.Errorf("must have encrypt pubkeys for private group %s", groupItem.GroupId)
		}

	} else {
		var err error
		ciperKey, err := hex.DecodeString(groupItem.CipherKey)
		if err != nil {
			return &trx, []byte(""), err
		}
		encryptdData, err = localcrypto.AesEncrypt(data, ciperKey)
		if err != nil {
			return &trx, []byte(""), err
		}
	}

	trx.Data = encryptdData
	trx.Version = version

	UpdateTrxTimeLimit(&trx)

	bytes, err := proto.Marshal(&trx)
	if err != nil {
		return &trx, []byte(""), err
	}
	hashed := localcrypto.Hash(bytes)
	return &trx, hashed, nil
}

func CreateTrx(nodename string, version string, groupItem *quorumpb.GroupItem, msgType quorumpb.TrxType, nonce int64, data []byte, encryptto ...[]string) (*quorumpb.Trx, error) {
	trx, hashed, err := CreateTrxWithoutSign(nodename, version, groupItem, msgType, int64(nonce), data, encryptto...)

	if err != nil {
		return trx, err
	}
	ks := localcrypto.GetKeystore()
	keyname := groupItem.GroupId
	signature, err := ks.SignByKeyName(keyname, hashed)
	if err != nil {
		return trx, err
	}

	trx.SenderSign = signature

	return trx, nil
}

func UpdateTrxTimeLimit(trx *quorumpb.Trx) {
	trx.TimeStamp = time.Now().UnixNano()
	timein := time.Now().Local().Add(time.Hour*time.Duration(Hours) +
		time.Minute*time.Duration(Mins) +
		time.Second*time.Duration(Sec))
	trx.Expired = timein.UnixNano()
}

func VerifyTrx(trx *quorumpb.Trx) (bool, error) {
	//clone trxMsg to verify
	clonetrxmsg := &quorumpb.Trx{
		TrxId:        trx.TrxId,
		Type:         trx.Type,
		GroupId:      trx.GroupId,
		SenderPubkey: trx.SenderPubkey,
		Nonce:        trx.Nonce,
		Data:         trx.Data,
		TimeStamp:    trx.TimeStamp,
		Version:      trx.Version,
		Expired:      trx.Expired}

	bytes, err := proto.Marshal(clonetrxmsg)
	if err != nil {
		return false, err
	}

	hashed := localcrypto.Hash(bytes)

	//create pubkey
	serializedpub, err := p2pcrypto.ConfigDecodeKey(trx.SenderPubkey)
	if err != nil {
		return false, err
	}

	pubkey, err := p2pcrypto.UnmarshalPublicKey(serializedpub)
	if err != nil {
		return false, err
	}

	verify, err := pubkey.Verify(hashed, trx.SenderSign)
	return verify, err
}
