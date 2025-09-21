package nftnl

import (
	"golang.org/x/sys/unix"
)

// https://github.com/torvalds/linux/blob/f83a4f2a4d8c485922fba3018a64fc8f4cfd315f/include/uapi/linux/netfilter/nf_tables.h#L1190
type CtAttrs struct {
	DReg      uint32
	Key       uint32
	Direction uint8
	SReg      uint32
}

func (a CtAttrs) ExprName() string {
	return "ct"
}

func (a *CtAttrs) marshal() ([]byte, error) {
	ae := NewAttributeEncoder()
	ae.Uint32(unix.NFTA_CT_KEY, a.Key)
	if a.DReg > 0 {
		ae.Uint32(unix.NFTA_CT_DREG, a.DReg)
	} else {
		ae.Uint32(unix.NFTA_CT_SREG, a.SReg)
	}

	switch a.Key {
	case unix.NFT_CT_SRC, unix.NFT_CT_DST, unix.NFT_CT_PROTO_SRC,
		unix.NFT_CT_PROTO_DST, unix.NFT_CT_SRC_IP, unix.NFT_CT_DST_IP,
		unix.NFT_CT_SRC_IP6, unix.NFT_CT_DST_IP6:
		ae.Uint8(unix.NFTA_CT_DIRECTION, a.Direction)
	}

	return ae.Encode()
}

func (a *CtAttrs) unmarshal(data []byte) error {
	ad, err := NewAttributeDecoder(data)
	if err != nil {
		return err
	}

	for ad.Next() {
		switch ad.Type() {
		case unix.NFTA_CT_DREG:
			a.DReg = ad.Uint32()
		case unix.NFTA_CT_KEY:
			a.Key = ad.Uint32()
		case unix.NFTA_CT_DIRECTION:
			a.Direction = ad.Uint8()
		case unix.NFTA_CT_SREG:
			a.SReg = ad.Uint32()
		}
	}

	return nil
}
