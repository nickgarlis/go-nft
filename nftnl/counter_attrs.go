package nftnl

import (
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// https://github.com/torvalds/linux/blob/f83a4f2a4d8c485922fba3018a64fc8f4cfd315f/include/uapi/linux/netfilter/nf_tables.h#L1265
type CounterAttrs struct {
	Bytes   uint64
	Packets uint64
}

func (CounterAttrs) ExprName() string {
	return "counter"
}

func (a *CounterAttrs) marshal() ([]byte, error) {
	ae := NewAttributeEncoder()
	ae.Uint64(unix.NFTA_COUNTER_BYTES, a.Bytes)
	ae.Uint64(unix.NFTA_COUNTER_PACKETS, a.Packets)
	return ae.Encode()
}

func (a *CounterAttrs) unmarshal(data []byte) error {
	ad, err := netlink.NewAttributeDecoder(data)
	if err != nil {
		return err
	}

	for ad.Next() {
		switch ad.Type() {
		case unix.NFTA_COUNTER_BYTES:
			a.Bytes = ad.Uint64()
		case unix.NFTA_COUNTER_PACKETS:
			a.Packets = ad.Uint64()
		}
	}

	return nil
}
