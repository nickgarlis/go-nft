package nftnl

import "golang.org/x/sys/unix"

type DataAttrs struct {
	Value        []byte
	VerdictAttrs *VerdictAttrs
}

func (a DataAttrs) ExprName() string {
	return "data"
}

func (a *DataAttrs) marshal() ([]byte, error) {
	ae := NewAttributeEncoder()
	ae.Bytes(unix.NFTA_DATA_VALUE, a.Value)
	if a.VerdictAttrs != nil {
		verdictData, err := a.VerdictAttrs.marshal()
		if err != nil {
			return nil, err
		}
		ae.Bytes(unix.NLA_F_NESTED|unix.NFTA_DATA_VERDICT, verdictData)
	}

	return ae.Encode()
}

func (a *DataAttrs) unmarshal(b []byte) error {
	ad, err := NewAttributeDecoder(b)
	if err != nil {
		return err
	}

	for ad.Next() {
		switch ad.Type() {
		case unix.NFTA_DATA_VALUE:
			a.Value = ad.Bytes()
		case unix.NFTA_DATA_VERDICT:
			a.VerdictAttrs = &VerdictAttrs{}
			if err := a.VerdictAttrs.unmarshal(ad.Bytes()); err != nil {
				return err
			}
		}
	}

	return nil
}
