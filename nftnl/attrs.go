package nftnl

import (
	"encoding/binary"
	"fmt"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

type Attrs interface {
	marshal() ([]byte, error)
	unmarshal(data []byte) error
}

func attrFactory(msgType uint16) (Attrs, error) {
	switch msgType {
	case unix.NFT_MSG_NEWTABLE, unix.NFT_MSG_GETTABLE, unix.NFT_MSG_DELTABLE:
		return &TableAttrs{}, nil
	case unix.NFT_MSG_NEWCHAIN, unix.NFT_MSG_GETCHAIN, unix.NFT_MSG_DELCHAIN:
		return &ChainAttrs{}, nil
	case unix.NFT_MSG_NEWRULE, unix.NFT_MSG_GETRULE, unix.NFT_MSG_DELRULE:
		return &RuleAttrs{}, nil
	case unix.NFT_MSG_NEWGEN, unix.NFT_MSG_GETGEN:
		return &GenAttrs{}, nil
	default:
		return nil, fmt.Errorf("unknown message type %d", msgType)
	}
}

func NewAttributeDecoder(b []byte) (*netlink.AttributeDecoder, error) {
	ad, err := netlink.NewAttributeDecoder(b)
	if err != nil {
		return nil, err
	}

	ad.ByteOrder = binary.BigEndian

	return ad, nil
}

func NewAttributeEncoder() *netlink.AttributeEncoder {
	ae := netlink.NewAttributeEncoder()

	ae.ByteOrder = binary.BigEndian

	return ae
}
