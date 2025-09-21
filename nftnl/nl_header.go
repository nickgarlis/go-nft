package nftnl

import (
	"fmt"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// NfHeader represents the netlink header combined with the NFGenMsg header.
type Header struct {
	// https://github.com/torvalds/linux/blob/f83a4f2a4d8c485922fba3018a64fc8f4cfd315f/include/uapi/linux/netfilter/nfnetlink.h#L61
	SubsysID uint16
	// https://github.com/torvalds/linux/blob/f83a4f2a4d8c485922fba3018a64fc8f4cfd315f/include/uapi/linux/netfilter/nf_tables.h#L110
	MsgType uint16
	Flags   netlink.HeaderFlags
}

func (h *Header) MsgTypeString() string {
	if h.SubsysID == unix.NFNL_SUBSYS_NFTABLES {
		switch h.MsgType {
		case unix.NFT_MSG_NEWTABLE:
			return "NFT_MSG_NEWTABLE"
		case unix.NFT_MSG_GETTABLE:
			return "NFT_MSG_GETTABLE"
		case unix.NFT_MSG_DELTABLE:
			return "NFT_MSG_DELTABLE"
		case unix.NFT_MSG_NEWCHAIN:
			return "NFT_MSG_NEWCHAIN"
		case unix.NFT_MSG_GETCHAIN:
			return "NFT_MSG_GETCHAIN"
		case unix.NFT_MSG_DELCHAIN:
			return "NFT_MSG_DELCHAIN"
		case unix.NFT_MSG_NEWRULE:
			return "NFT_MSG_NEWRULE"
		case unix.NFT_MSG_GETRULE:
			return "NFT_MSG_GETRULE"
		case unix.NFT_MSG_DELRULE:
			return "NFT_MSG_DELRULE"
		}
	}
	return fmt.Sprintf("unknown msg type %d", h.MsgType)
}

func (h *Header) marshal() netlink.Header {
	var headerType netlink.HeaderType
	if h.SubsysID == unix.NFNL_SUBSYS_NFTABLES {
		headerType = netlink.HeaderType((h.SubsysID << 8) | h.MsgType)
	} else {
		headerType = netlink.HeaderType(h.SubsysID)
	}
	nlHeader := netlink.Header{
		Type:  headerType,
		Flags: h.Flags,
	}

	return nlHeader
}

func (h *Header) unmarshal(header netlink.Header) error {
	h.MsgType = uint16(header.Type & 0xff)
	h.Flags = header.Flags
	return nil
}
