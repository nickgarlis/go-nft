package nftnl

import (
	"golang.org/x/sys/unix"
)

type BitwiseAttrs struct {
	SReg uint32
	DReg uint32
	Len  uint32
	Mask *DataAttrs
	Xor  *DataAttrs
}

func (a BitwiseAttrs) ExprName() string {
	return "bitwise"
}

func (a *BitwiseAttrs) marshal() ([]byte, error) {
	ae := NewAttributeEncoder()

	ae.Uint32(unix.NFTA_BITWISE_DREG, a.DReg)
	ae.Uint32(unix.NFTA_BITWISE_SREG, a.SReg)
	ae.Uint32(unix.NFTA_BITWISE_LEN, a.Len)
	if a.Mask != nil {
		b, err := a.Mask.marshal()
		if err != nil {
			return nil, err
		}
		ae.Bytes(unix.NLA_F_NESTED|unix.NFTA_BITWISE_MASK, b)
	}
	if a.Xor != nil {
		b, err := a.Xor.marshal()
		if err != nil {
			return nil, err
		}
		ae.Bytes(unix.NLA_F_NESTED|unix.NFTA_BITWISE_XOR, b)
	}

	return ae.Encode()
}

func (a *BitwiseAttrs) unmarshal(data []byte) error {
	ad, err := NewAttributeDecoder(data)
	if err != nil {
		return err
	}

	for ad.Next() {
		switch ad.Type() {
		case unix.NFTA_BITWISE_SREG:
			a.SReg = ad.Uint32()
		case unix.NFTA_BITWISE_DREG:
			a.DReg = ad.Uint32()
		case unix.NFTA_BITWISE_LEN:
			a.Len = ad.Uint32()
		case unix.NFTA_BITWISE_MASK:
			a.Mask = &DataAttrs{}
			if err := a.Mask.unmarshal(ad.Bytes()); err != nil {
				return err
			}
		case unix.NFTA_BITWISE_XOR:
			a.Xor = &DataAttrs{}
			if err := a.Xor.unmarshal(ad.Bytes()); err != nil {
				return err
			}
		}
	}

	return nil
}
