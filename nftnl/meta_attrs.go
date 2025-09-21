package nftnl

import (
	"golang.org/x/sys/unix"
)

// https://github.com/torvalds/linux/blob/f83a4f2a4d8c485922fba3018a64fc8f4cfd315f/include/uapi/linux/netfilter/nf_tables.h#L1069
type MetaAttrs struct {
	DReg uint32
	Key  uint32
	SReg uint32
}

func (a MetaAttrs) ExprName() string {
	return "meta"
}

func (a *MetaAttrs) marshal() ([]byte, error) {
	ae := NewAttributeEncoder()
	ae.Uint32(unix.NFTA_META_KEY, a.Key)
	if a.DReg > 0 {
		ae.Uint32(unix.NFTA_META_DREG, a.DReg)
	} else {
		ae.Uint32(unix.NFTA_META_SREG, a.SReg)
	}

	return ae.Encode()
}

func (a *MetaAttrs) unmarshal(data []byte) error {
	ad, err := NewAttributeDecoder(data)
	if err != nil {
		return err
	}

	for ad.Next() {
		switch ad.Type() {
		case unix.NFTA_META_DREG:
			a.DReg = ad.Uint32()
		case unix.NFTA_META_KEY:
			a.Key = ad.Uint32()
		case unix.NFTA_META_SREG:
			a.SReg = ad.Uint32()
		}
	}

	return nil
}
