package nftnl

import (
	"golang.org/x/sys/unix"
)

// https://github.com/torvalds/linux/blob/f83a4f2a4d8c485922fba3018a64fc8f4cfd315f/include/uapi/linux/netfilter/nf_tables.h#L689
type CmpAttrs struct {
	SReg uint32
	Op   uint32
	Data *DataAttrs
}

func (a CmpAttrs) ExprName() string {
	return "cmp"
}

func (a *CmpAttrs) marshal() ([]byte, error) {
	ae := NewAttributeEncoder()

	ae.Uint32(unix.NFTA_CMP_SREG, a.SReg)
	ae.Uint32(unix.NFTA_CMP_OP, a.Op)

	if a.Data != nil {
		b, err := a.Data.marshal()
		if err != nil {
			return nil, err
		}
		ae.Bytes(unix.NLA_F_NESTED|unix.NFTA_CMP_DATA, b)
	}

	return ae.Encode()
}

func (a *CmpAttrs) unmarshal(data []byte) error {
	ad, err := NewAttributeDecoder(data)
	if err != nil {
		return err
	}

	for ad.Next() {
		switch ad.Type() {
		case unix.NFTA_CMP_SREG:
			a.SReg = ad.Uint32()
		case unix.NFTA_CMP_OP:
			a.Op = ad.Uint32()
		case unix.NFTA_CMP_DATA:
			a.Data = &DataAttrs{}
			if err := a.Data.unmarshal(ad.Bytes()); err != nil {
				return err
			}
		}
	}

	return nil
}
