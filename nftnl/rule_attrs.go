package nftnl

import (
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

type RuleAttrs struct {
	Table       string
	Chain       string
	Handle      uint64
	Expressions []ExprAttrs
	Position    uint64
	UserData    []byte
	ID          uint32
	PositionID  uint32
	ChainID     uint32
}

func (a *RuleAttrs) marshal() ([]byte, error) {
	ae := NewAttributeEncoder()
	ae.String(unix.NFTA_RULE_TABLE, a.Table)
	if a.Chain != "" {
		ae.String(unix.NFTA_RULE_CHAIN, a.Chain)
	}
	if a.Handle > 0 {
		ae.Uint64(unix.NFTA_RULE_HANDLE, a.Handle)
	}
	if a.Position > 0 {
		ae.Uint64(unix.NFTA_RULE_POSITION, a.Position)
	}
	if len(a.UserData) > 0 {
		ae.Bytes(unix.NFTA_RULE_USERDATA, a.UserData)
	}
	if len(a.Expressions) > 0 {
		ae.Nested(unix.NFTA_RULE_EXPRESSIONS, func(nae *netlink.AttributeEncoder) error {
			for _, a := range a.Expressions {
				data, err := a.marshal()
				if err != nil {
					return err
				}
				nae.Bytes(unix.NLA_F_NESTED|unix.NFTA_LIST_ELEM, data)
			}
			return nil
		})
	}
	if a.ID > 0 {
		ae.Uint32(unix.NFTA_RULE_ID, a.ID)
	}

	return ae.Encode()
}

func (a *RuleAttrs) unmarshal(data []byte) error {
	ad, err := NewAttributeDecoder(data)
	if err != nil {
		return err
	}

	for ad.Next() {
		switch ad.Type() {
		case unix.NFTA_RULE_TABLE:
			a.Table = ad.String()
		case unix.NFTA_RULE_CHAIN:
			a.Chain = ad.String()
		case unix.NFTA_RULE_HANDLE:
			a.Handle = ad.Uint64()
		case unix.NFTA_RULE_POSITION:
			a.Position = ad.Uint64()
		case unix.NFTA_RULE_USERDATA:
			a.UserData = ad.Bytes()
		case unix.NFTA_RULE_EXPRESSIONS:
			ad.Nested(func(nad *netlink.AttributeDecoder) error {
				for nad.Next() {
					switch nad.Type() {
					case unix.NFTA_LIST_ELEM:
						expr := ExprAttrs{}
						if err := expr.unmarshal(nad.Bytes()); err != nil {
							return err
						}
						a.Expressions = append(a.Expressions, expr)
					}
				}
				return nil
			})
		case unix.NFTA_RULE_ID:
			a.ID = ad.Uint32()
		}
	}

	return nil
}
