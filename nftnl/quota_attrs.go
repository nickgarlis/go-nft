package nftnl

import "golang.org/x/sys/unix"

// https://github.com/torvalds/linux/blob/f83a4f2a4d8c485922fba3018a64fc8f4cfd315f/include/uapi/linux/netfilter/nf_tables.h#L1372
type QuotaAttrs struct {
	Bytes    uint64
	Flags    uint32
	Consumed uint64
}

func (a QuotaAttrs) ExprName() string {
	return "quota"
}

func (a *QuotaAttrs) marshal() ([]byte, error) {
	ae := NewAttributeEncoder()
	ae.Uint64(unix.NFTA_QUOTA_BYTES, a.Bytes)
	if a.Flags > 0 {
		ae.Uint32(unix.NFTA_QUOTA_FLAGS, a.Flags)
	}
	if a.Consumed > 0 {
		ae.Uint64(unix.NFTA_QUOTA_CONSUMED, a.Consumed)
	}

	return ae.Encode()
}

func (a *QuotaAttrs) unmarshal(data []byte) error {
	ad, err := NewAttributeDecoder(data)
	if err != nil {
		return err
	}

	for ad.Next() {
		switch ad.Type() {
		case unix.NFTA_QUOTA_BYTES:
			a.Bytes = ad.Uint64()
		case unix.NFTA_QUOTA_FLAGS:
			a.Flags = ad.Uint32()
		case unix.NFTA_QUOTA_CONSUMED:
			a.Consumed = ad.Uint64()
		}
	}

	return nil
}
