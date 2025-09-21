package nftnl

import (
	"github.com/mdlayher/netlink"
	"github.com/nickgarlis/go-nft/unixext"
	"golang.org/x/sys/unix"
)

// https://github.com/torvalds/linux/blob/f83a4f2a4d8c485922fba3018a64fc8f4cfd315f/include/uapi/linux/netfilter/nf_tables.h#L451
type SetElemAttrs struct {
	Key         *DataAttrs
	Data        *DataAttrs
	Flags       uint32
	Timeout     uint64
	Expiration  uint64
	UserData    []byte
	Expr        ExprDataAttrs
	ObjRef      string
	KeyEnd      *DataAttrs
	Expressions []ExprDataAttrs
}

func (a *SetElemAttrs) marshal() ([]byte, error) {
	ae := NewAttributeEncoder()
	if a.Key != nil {
		keyData, err := a.Key.marshal()
		if err != nil {
			return nil, err
		}
		ae.Bytes(unix.NLA_F_NESTED|unix.NFTA_SET_ELEM_KEY, keyData)
	}
	if a.Data != nil {
		dataData, err := a.Data.marshal()
		if err != nil {
			return nil, err
		}
		ae.Bytes(unix.NLA_F_NESTED|unix.NFTA_SET_ELEM_DATA, dataData)
	}
	if a.Flags != 0 {
		ae.Uint32(unix.NFTA_SET_ELEM_FLAGS, a.Flags)
	}
	if a.Timeout != 0 {
		ae.Uint64(unix.NFTA_SET_ELEM_TIMEOUT, a.Timeout)
	}
	if a.Expiration != 0 {
		ae.Uint64(unix.NFTA_SET_ELEM_EXPIRATION, a.Expiration)
	}
	if len(a.UserData) > 0 {
		ae.Bytes(unix.NFTA_SET_ELEM_USERDATA, a.UserData)
	}
	if a.Expr != nil {
		exprData, err := a.Expr.marshal()
		if err != nil {
			return nil, err
		}
		ae.Bytes(unix.NLA_F_NESTED|unix.NFTA_SET_ELEM_EXPR, exprData)
	}
	if a.ObjRef != "" {
		ae.String(unix.NFTA_SET_ELEM_OBJREF, a.ObjRef)
	}
	if a.KeyEnd != nil {
		keyEndData, err := a.KeyEnd.marshal()
		if err != nil {
			return nil, err
		}
		ae.Bytes(unix.NLA_F_NESTED|unixext.NFTA_SET_ELEM_KEY_END, keyEndData)
	}
	// if len(a.Expressions) > 0 {
	// 	exprsData, err := marshalExprs(a.Expressions)
	// 	if err != nil {
	// 		return nil, err
	// 	}
	// 	ae.Bytes(unix.NLA_F_NESTED|unixext.NFTA_SET_ELEM_EXPRESSIONS, exprsData)
	// }

	return ae.Encode()
}

func (a *SetElemAttrs) unmarshal(b []byte) error {
	ad, err := NewAttributeDecoder(b)
	if err != nil {
		return err
	}

	for ad.Next() {
		switch ad.Type() {
		case unix.NFTA_SET_ELEM_KEY:
			ad.Nested(func(nad *netlink.AttributeDecoder) error {
				a.Key = &DataAttrs{}
				return a.Key.unmarshal(nad.Bytes())
			})
		case unix.NFTA_SET_ELEM_DATA:
			ad.Nested(func(nad *netlink.AttributeDecoder) error {
				a.Data = &DataAttrs{}
				return a.Data.unmarshal(nad.Bytes())
			})
		case unix.NFTA_SET_ELEM_FLAGS:
			a.Flags = ad.Uint32()
		case unix.NFTA_SET_ELEM_TIMEOUT:
			a.Timeout = ad.Uint64()
		case unix.NFTA_SET_ELEM_EXPIRATION:
			a.Expiration = ad.Uint64()
		case unix.NFTA_SET_ELEM_USERDATA:
			a.UserData = ad.Bytes()
		case unix.NFTA_SET_ELEM_EXPR:
			// ad.Nested(func(nad *netlink.AttributeDecoder) error {
			// 	a.Expr = &ExprAttrs{}
			// 	return a.Expr.unmarshal(nad.Bytes())
			// })
		case unix.NFTA_SET_ELEM_OBJREF:
			a.ObjRef = ad.String()
		case unixext.NFTA_SET_ELEM_KEY_END:
			ad.Nested(func(nad *netlink.AttributeDecoder) error {
				a.KeyEnd = &DataAttrs{}
				return a.KeyEnd.unmarshal(nad.Bytes())
			})
			// case unixext.NFTA_SET_ELEM_EXPRESSIONS:
			// 	exprData := ad.Bytes()
			// 	exprAd, err := NewAttributeDecoder(exprData)
			// 	if err != nil {
			// 		return err
			// 	}

			// 	for exprAd.Next() {
			// 		expr := ExprAttrs{}
			// 		if err := expr.unmarshal(exprAd.Bytes()); err != nil {
			// 			return err
			// 		}
			// 		a.Expressions = append(a.Expressions, expr)
			// 	}
			// }
		}
	}
	return nil
}
