package provingwork

import (
	"bytes"
	"fmt"
	"reflect"

	"math/big"

	"crypto/sha1"

	"encoding/base64"
	"encoding/binary"
	"encoding/json"
)

type HashCash struct {
	Counter  int64  `json:"counter"`
	Resource []byte `json:"resource"`

	*WorkOptions
}

func NewHashCash(resource []byte, opts ...*WorkOptions) *HashCash {
	hc := HashCash{Resource: resource}

	if len(opts) != 0 {
		hc.WorkOptions = opts[0]
	} else {
		hc.WorkOptions = &WorkOptions{}
	}

	setDefaultWorkOptions(hc.WorkOptions)

	return &hc
}

func (wo HashCash) ToJson() ([]byte, error) {

	return json.Marshal(wo)
}

func Check(data []byte, toProof []byte, opts ...*WorkOptions) (hc *HashCash, err error) {

	hc = NewHashCash(nil, opts...)

	err = json.Unmarshal(data, hc)
	if err != nil {
		return
	}

	ok := reflect.DeepEqual(hc.Resource, toProof)
	if !ok {

		err = fmt.Errorf("proofs differ received: %s expected: %s")
		return
	}

	ok = hc.Check()
	if !ok {

		err = fmt.Errorf("proof is not valid")
		return
	}

	return
}

func (hc HashCash) Check() bool {
	if hc.ZeroCount() >= hc.BitStrength {
		return true
	}
	return false
}

func (hc HashCash) CounterBytes() []byte {
	var buf bytes.Buffer
	binary.Write(&buf, binary.BigEndian, hc.Counter)
	return buf.Bytes()
}

func (hc *HashCash) FindProof() {
	for {
		if hc.Check() {
			return
		}
		hc.Counter++
	}
}

func (hc HashCash) Hash() string {

	return fmt.Sprintf(
		"1:%v:%v:%v:%v:%v:%v",
		hc.BitStrength,
		string(hc.Resource),
		string(hc.Extension),
		base64.StdEncoding.EncodeToString(hc.Salt),
		base64.StdEncoding.EncodeToString(hc.CounterBytes()),
	)
}

func (hc HashCash) ZeroCount() int {
	digest := sha1.Sum([]byte(hc.Hash()))
	digestHex := new(big.Int).SetBytes(digest[:])
	return ((sha1.Size * 8) - digestHex.BitLen())
}
