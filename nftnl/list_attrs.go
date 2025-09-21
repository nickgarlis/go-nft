package nftnl

import "golang.org/x/sys/unix"

// https://github.com/torvalds/linux/blob/f83a4f2a4d8c485922fba3018a64fc8f4cfd315f/include/uapi/linux/netfilter/nf_tables.h#L153
type ListAttrs struct {
	ListElem []Attrs
}

func (a *ListAttrs) marshal() ([]byte, error) {
	ae := NewAttributeEncoder()
	for _, le := range a.ListElem {
		b, err := le.marshal()
		if err != nil {
			return nil, err
		}
		ae.Bytes(unix.NLA_F_NESTED|unix.NFTA_LIST_ELEM, b)
	}
	return ae.Encode()
}

func (a *ListAttrs) unmarshal(data []byte) error {
	ad, err := NewAttributeDecoder(data)
	if err != nil {
		return err
	}

	for ad.Next() {
		switch ad.Type() {
		case unix.NFTA_LIST_ELEM:
			// TODO: implement unmarshaling for list elements
			// le := &Attrs{}
			// if err := le.unmarshal(ad.Bytes()); err != nil {
			// 	return err
			// }
			// a.ListElem = append(a.ListElem, *le)
		}
	}

	return nil
}
