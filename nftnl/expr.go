package nftnl

import (
	"fmt"

	"golang.org/x/sys/unix"
)

type ExprDataAttrs interface {
	ExprName() string
	marshal() ([]byte, error)
	unmarshal(data []byte) error
}

type ExprAttrs struct {
	Name string
	Data ExprDataAttrs
}

func (a *ExprAttrs) marshal() ([]byte, error) {
	ae := NewAttributeEncoder()
	ae.String(unix.NFTA_EXPR_NAME, a.Data.ExprName())
	data, err := a.Data.marshal()
	if err != nil {
		return nil, err
	}
	ae.Bytes(unix.NLA_F_NESTED|unix.NFTA_EXPR_DATA, data)

	return ae.Encode()
}

func (a *ExprAttrs) unmarshal(data []byte) error {
	ad, err := NewAttributeDecoder(data)
	if err != nil {
		return err
	}

	for ad.Next() {
		switch ad.Type() {
		case unix.NFTA_EXPR_NAME:
			a.Name = ad.String()
		case unix.NFTA_EXPR_DATA:
			exprData, err := exprDataFactory(a.Name)
			if err != nil {
				return err
			}
			a.Data = exprData
			if err := a.Data.unmarshal(ad.Bytes()); err != nil {
				return err
			}
		}
	}

	return nil
}

func exprDataFactory(name string) (ExprDataAttrs, error) {
	switch name {
	case "bitwise":
		return &BitwiseAttrs{}, nil
	case "cmp":
		return &CmpAttrs{}, nil
	case "counter":
		return &CounterAttrs{}, nil
	case "ct":
		return &CtAttrs{}, nil
	case "immediage":
		return &ImmediateAttrs{}, nil
	case "meta":
		return &MetaAttrs{}, nil
	case "payload":
		return &PayloadAttrs{}, nil
	case "verdict":
		return &VerdictAttrs{}, nil
	default:
		return nil, fmt.Errorf("unknown expr name %q", name)
	}
}

func unmarshalExpr(data []byte) (*ExprAttrs, error) {
	ad, err := NewAttributeDecoder(data)
	if err != nil {
		return nil, err
	}

	var exprAttrs = &ExprAttrs{}

	for ad.Next() {
		switch ad.Type() {
		case unix.NFTA_EXPR_NAME:
			exprAttrs.Name = ad.String()
		case unix.NFTA_EXPR_DATA:
			exprData, err := exprDataFactory(exprAttrs.Name)
			if err != nil {
				return nil, err
			}
			exprData.unmarshal(ad.Bytes())
			exprAttrs.Data = exprData
		}
	}

	return exprAttrs, nil
}
