package provingwork

import "crypto/rand"

var (
	DefaultBitStrength = 22
	DefaultSaltSize    = 16
)

type WorkOptions struct {
	BitStrength int    `json:"-"`
	Extension   []byte `json:"extension,omitempty"`
	Salt        []byte `json:"salt,omitempty"`
}

func setDefaultWorkOptions(wo *WorkOptions) {

	if wo.BitStrength == 0 {
		wo.BitStrength = DefaultBitStrength
	}

	if len(wo.Salt) == 0 {
		wo.Salt = make([]byte, DefaultSaltSize)
		rand.Read(wo.Salt)
	}
}
