package nft

import (
	"net/netip"

	"github.com/mdlayher/netlink"
	"github.com/nickgarlis/go-nft/nftnl"
	"golang.org/x/sys/unix"
)

type SetElem struct {
	Prefix *netip.Prefix
	Addr   *netip.Addr
	Port   uint16

	Timeout uint64
}

type Set struct {
	Family uint8
	Set    string
	SetID  uint32
}

func (b *Batch) AddSetElements(setElemL *nftnl.SetElemListAttrs) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.nftnlBatch.Add(nftnl.Msg{
		Header: nftnl.Header{
			SubsysID: unix.NFNL_SUBSYS_NFTABLES,
			MsgType:  unix.NFT_MSG_NEWSETELEM,
			Flags:    netlink.Request | netlink.Acknowledge | netlink.Create,
		},
		NfGenMsg: nftnl.NfGenMsg{
			Family: unix.NFPROTO_UNSPEC,
		},
		Attrs: setElemL,
	})
	return nil
}
