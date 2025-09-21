package nftnl

import (
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

type SetElemListAttrs struct {
	Table    string
	Set      string
	Elements []SetElemAttrs
	SetID    uint64
}

func (a *SetElemListAttrs) marshal() ([]byte, error) {
	ae := NewAttributeEncoder()
	ae.String(unix.NFTA_SET_ELEM_LIST_TABLE, a.Table)
	ae.String(unix.NFTA_SET_ELEM_LIST_SET, a.Set)
	if a.SetID > 0 {
		ae.Uint64(unix.NFTA_SET_ELEM_LIST_SET_ID, a.SetID)
	}
	if len(a.Elements) > 0 {
		ae.Nested(unix.NFTA_SET_ELEM_LIST_ELEMENTS, func(nae *netlink.AttributeEncoder) error {
			for i, elem := range a.Elements {
				elemData, err := elem.marshal()
				if err != nil {
					return err
				}
				nae.Bytes(unix.NLA_F_NESTED|uint16(i), elemData)
			}
			return nil
		})
	}

	return ae.Encode()
}

func (a *SetElemListAttrs) unmarshal(b []byte) error {
	ad, err := NewAttributeDecoder(b)
	if err != nil {
		return err
	}

	for ad.Next() {
		switch ad.Type() {
		case unix.NFTA_SET_ELEM_LIST_TABLE:
			a.Table = ad.String()
		case unix.NFTA_SET_ELEM_LIST_SET:
			a.Set = ad.String()
		case unix.NFTA_SET_ELEM_LIST_SET_ID:
			a.SetID = ad.Uint64()
		case unix.NFTA_SET_ELEM_LIST_ELEMENTS:
			ad.Nested(func(nad *netlink.AttributeDecoder) error {
				for nad.Next() {
					elem := SetElemAttrs{}
					if err := elem.unmarshal(nad.Bytes()); err != nil {
						return err
					}
					a.Elements = append(a.Elements, elem)
				}
				return nil
			})
		}
	}

	return nil
}
