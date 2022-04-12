package data

import (
	"encoding/hex"
	"fmt"
	guuid "github.com/google/uuid"
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

func UpdateTrxTimeLimit(trx *quorumpb.Trx) {
	trx.TimeStamp = time.Now().UnixNano()
	timein := time.Now().Local().Add(time.Hour*time.Duration(Hours) +
		time.Minute*time.Duration(Mins) +
		time.Second*time.Duration(Sec))
	trx.Expired = timein.UnixNano()
}
