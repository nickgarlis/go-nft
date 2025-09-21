package nftnl

import (
	"golang.org/x/sys/unix"
)

// https://github.com/torvalds/linux/blob/f83a4f2a4d8c485922fba3018a64fc8f4cfd315f/include/uapi/linux/netfilter/nf_tables.h#L862
type PayloadAttrs struct {
	DReg       uint32
	Base       uint32
	Offset     uint32
	Len        uint32
	SReg       uint32
	CSumType   uint32
	CSumOffset uint32
	CSumFlags  uint32
}

func (a PayloadAttrs) ExprName() string {
	return "payload"
}

func (a *PayloadAttrs) marshal() ([]byte, error) {
	ae := NewAttributeEncoder()

	if a.DReg > 0 {
		ae.Uint32(unix.NFTA_PAYLOAD_DREG, a.DReg)
	} else {
		ae.Uint32(unix.NFTA_PAYLOAD_SREG, a.SReg)
	}

	ae.Uint32(unix.NFTA_PAYLOAD_BASE, a.Base)
	ae.Uint32(unix.NFTA_PAYLOAD_OFFSET, a.Offset)
	ae.Uint32(unix.NFTA_PAYLOAD_LEN, a.Len)

	if a.CSumType > 0 {
		ae.Uint32(unix.NFTA_PAYLOAD_CSUM_TYPE, a.CSumType)
		ae.Uint32(unix.NFTA_PAYLOAD_CSUM_OFFSET, a.CSumOffset)
		ae.Uint32(unix.NFTA_PAYLOAD_CSUM_FLAGS, a.CSumFlags)
	}

	return ae.Encode()
}

func (a *PayloadAttrs) unmarshal(data []byte) error {
	ad, err := NewAttributeDecoder(data)
	if err != nil {
		return err
	}

	for ad.Next() {
		switch ad.Type() {
		case unix.NFTA_PAYLOAD_DREG:
			a.DReg = ad.Uint32()
		case unix.NFTA_PAYLOAD_BASE:
			a.Base = ad.Uint32()
		case unix.NFTA_PAYLOAD_OFFSET:
			a.Offset = ad.Uint32()
		case unix.NFTA_PAYLOAD_LEN:
			a.Len = ad.Uint32()
		case unix.NFTA_PAYLOAD_SREG:
			a.SReg = ad.Uint32()
		case unix.NFTA_PAYLOAD_CSUM_TYPE:
			a.CSumType = ad.Uint32()
		case unix.NFTA_PAYLOAD_CSUM_OFFSET:
			a.CSumOffset = ad.Uint32()
		case unix.NFTA_PAYLOAD_CSUM_FLAGS:
			a.CSumFlags = ad.Uint32()
		}
	}

	return nil
}
