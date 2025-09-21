package nftnl

import (
	"github.com/nickgarlis/go-nft/unixext"
	"golang.org/x/sys/unix"
)

// https://github.com/torvalds/linux/blob/f83a4f2a4d8c485922fba3018a64fc8f4cfd315f/include/uapi/linux/netfilter/nf_tables.h#L531
type VerdictAttrs struct {
	Code    uint32
	Chain   string
	ChainID uint32
}

func (a VerdictAttrs) ExprName() string {
	return "verdict"
}

// TODO: something is wrong here
func (a *VerdictAttrs) marshal() ([]byte, error) {
	ae := NewAttributeEncoder()
	ae.Uint32(unix.NFTA_VERDICT_CODE, a.Code)
	if a.Chain != "" {
		ae.String(unix.NFTA_VERDICT_CHAIN, a.Chain)
	}
	if a.ChainID != 0 {
		ae.Uint32(unixext.NFTA_VERDICT_CHAINID, a.ChainID)
	}

	return ae.Encode()
}

func (a *VerdictAttrs) unmarshal(b []byte) error {
	ad, err := NewAttributeDecoder(b)
	if err != nil {
		return err
	}

	for ad.Next() {
		switch ad.Type() {
		case unix.NFTA_VERDICT_CODE:
			a.Code = ad.Uint32()
		case unix.NFTA_VERDICT_CHAIN:
			a.Chain = ad.String()
		case unixext.NFTA_VERDICT_CHAINID:
			a.ChainID = ad.Uint32()
		}
	}

	return nil
}
