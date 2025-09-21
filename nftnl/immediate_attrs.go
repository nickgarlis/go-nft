package nftnl

import (
	"fmt"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// https://github.com/torvalds/linux/blob/8b789f2b7602a818e7c7488c74414fae21392b63/include/uapi/linux/netfilter/nf_tables.h#L560
type ImmediateAttrs struct {
	DReg uint32
	Data ExprDataAttrs
}

func (a ImmediateAttrs) ExprName() string {
	return "immediate"
}

func (a *ImmediateAttrs) marshal() ([]byte, error) {
	ae := NewAttributeEncoder()
	if a.Data != nil {
		switch a.Data.(type) {
		case *VerdictAttrs:
			// override any user-provided value
			// not sure whether this is the caller's responsibility
			a.DReg = unix.NFT_REG_VERDICT
			ae.Uint32(unix.NFTA_IMMEDIATE_DREG, a.DReg)
			ae.Nested(unix.NFTA_IMMEDIATE_DATA, func(nae *netlink.AttributeEncoder) error {
				data, err := a.Data.marshal()
				if err != nil {
					return err
				}
				nae.Bytes(unix.NLA_F_NESTED|unix.NFTA_DATA_VERDICT, data)
				return nil
			})
		default:
			return nil, fmt.Errorf("unsupported immediate data expr type %T", a.Data)
		}
	}

	return ae.Encode()
}

func (a *ImmediateAttrs) unmarshal(data []byte) error {
	ad, err := NewAttributeDecoder(data)
	if err != nil {
		return err
	}

	for ad.Next() {
		switch ad.Type() {
		case unix.NFTA_IMMEDIATE_DREG:
			a.DReg = ad.Uint32()
		case unix.NFTA_IMMEDIATE_DATA:
			ad.Nested(func(nad *netlink.AttributeDecoder) error {
				for nad.Next() {
					switch nad.Type() {
					case unix.NFTA_DATA_VERDICT:
						a.Data = &VerdictAttrs{}
						if err := a.Data.unmarshal(nad.Bytes()); err != nil {
							return err
						}
					default:
						return fmt.Errorf("unsupported immediate data expr attr type %d", nad.Type())
					}
				}
				return nil
			})
		}
	}

	return nil
}
