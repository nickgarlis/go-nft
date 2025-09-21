package nftnl

import (
	"github.com/mdlayher/netlink"
	"github.com/nickgarlis/go-nft/unixext"
	"golang.org/x/sys/unix"
)

// https://github.com/torvalds/linux/blob/f83a4f2a4d8c485922fba3018a64fc8f4cfd315f/include/uapi/linux/netfilter/nf_tables.h#L203
type TableAttrs struct {
	Name     string
	Flags    uint32
	Use      uint32
	Handle   uint64
	UserData []byte
	Owner    uint32
}

func (a *TableAttrs) marshal() ([]byte, error) {
	attrs := []netlink.Attribute{
		{Type: unix.NFTA_TABLE_NAME, Data: []byte(a.Name + "\x00")},
		{Type: unix.NFTA_TABLE_FLAGS, Data: []byte{0, 0, 0, 0}},
	}

	ae := NewAttributeEncoder()

	ae.String(unix.NFTA_TABLE_NAME, a.Name)
	ae.Uint32(unix.NFTA_TABLE_FLAGS, a.Flags)
	if a.Use > 0 {
		ae.Uint32(unix.NFTA_TABLE_USE, a.Use)
	}
	if a.Handle > 0 {
		ae.Uint64(unixext.NFTA_TABLE_HANDLE, a.Handle)
	}
	if len(a.UserData) > 0 {
		ae.Bytes(unixext.NFTA_TABLE_USERDATA, a.UserData)
	}
	if a.Owner > 0 {
		ae.Uint32(unixext.NFTA_TABLE_OWNER, a.Owner)
	}

	return netlink.MarshalAttributes(attrs)
}

func (a *TableAttrs) unmarshal(data []byte) error {
	ad, err := netlink.NewAttributeDecoder(data)
	if err != nil {
		return err
	}

	for ad.Next() {
		switch ad.Type() {
		case unix.NFTA_TABLE_NAME:
			a.Name = ad.String()
		case unix.NFTA_TABLE_FLAGS:
			a.Flags = ad.Uint32()
		case unix.NFTA_TABLE_USE:
			a.Use = ad.Uint32()
		case unixext.NFTA_TABLE_HANDLE:
			a.Handle = ad.Uint64()
		case unixext.NFTA_TABLE_USERDATA:
			a.UserData = ad.Bytes()
		case unixext.NFTA_TABLE_OWNER:
			a.Owner = ad.Uint32()
		}
	}

	return nil
}
