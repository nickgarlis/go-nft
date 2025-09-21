package nft

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"

	"github.com/nickgarlis/go-nft/nftnl"
	"golang.org/x/sys/unix"
)

func extractAttrs[T nftnl.Attrs](results []nftnl.Msg) ([]T, error) {
	attrs := make([]T, len(results))
	for i, r := range results {
		attr, ok := r.Attrs.(T)
		if !ok {
			return nil, fmt.Errorf("unmarshal error: expected %T, got %T", *new(T), r.Attrs)
		}
		attrs[i] = attr
	}
	return attrs, nil
}

func prefixExpr(prefix *netip.Prefix, src bool) []nftnl.ExprAttrs {
	var exprs []nftnl.ExprAttrs
	if prefix == nil {
		return exprs
	}

	addr := prefix.Addr()

	var offset uint32 = 12 // IPv4 src/dst offset
	if addr.Is6() {
		offset = 8 // IPv6 src/dst offset
	}

	if !src {
		offset += uint32(len(addr.AsSlice()))
	}

	length := uint32(len(addr.AsSlice()))
	mask := net.CIDRMask(prefix.Bits(), addr.BitLen())

	exprs = appendExpr(exprs,
		&nftnl.PayloadAttrs{
			DReg:   1,
			Base:   unix.NFT_PAYLOAD_NETWORK_HEADER,
			Offset: offset,
			Len:    length,
		},
		&nftnl.BitwiseAttrs{
			SReg: 1,
			DReg: 1,
			Len:  length,
			Mask: &nftnl.DataAttrs{
				Value: mask,
			},
			Xor: &nftnl.DataAttrs{
				Value: make([]byte, length),
			},
		},
		&nftnl.CmpAttrs{
			SReg: 1,
			Op:   unix.NFT_CMP_EQ,
			Data: &nftnl.DataAttrs{
				Value: addr.AsSlice(),
			},
		},
	)

	return exprs
}

// TODO: Double check if this is correct
func prefixFromExpr(attr *nftnl.BitwiseAttrs) *netip.Prefix {
	if attr.Mask == nil {
		return nil
	}
	prefixLen := 0
	for _, b := range attr.Mask.Value {
		for i := 7; i >= 0; i-- {
			if (b & (1 << i)) != 0 {
				prefixLen++
			} else {
				break
			}
		}
	}
	var addr netip.Addr
	if len(attr.Mask.Value) == net.IPv4len {
		addr = netip.AddrFrom4([4]byte{})
	} else if len(attr.Mask.Value) == net.IPv6len {
		addr = netip.AddrFrom16([16]byte{})
	} else {
		return nil
	}
	prefix := netip.PrefixFrom(addr, prefixLen)
	return &prefix
}

func addrExpr(addr *netip.Addr, isSrc bool) []nftnl.ExprAttrs {
	var exprs []nftnl.ExprAttrs

	var offset uint32 = 12 // IPv4 src/dst offset
	if addr.Is6() {
		offset = 8 // IPv6 src/dst offset
	}
	if !isSrc {
		offset += uint32(len(addr.AsSlice()))
	}
	length := uint32(len(addr.AsSlice()))

	exprs = appendExpr(exprs,
		&nftnl.PayloadAttrs{
			DReg:   1,
			Base:   unix.NFT_PAYLOAD_NETWORK_HEADER,
			Offset: offset,
			Len:    length,
		},
		&nftnl.CmpAttrs{
			SReg: 1,
			Op:   unix.NFT_CMP_EQ,
			Data: &nftnl.DataAttrs{
				Value: addr.AsSlice(),
			},
		},
	)

	return exprs
}

func ctStateExpr(states []CtState) []nftnl.ExprAttrs {
	var exprs []nftnl.ExprAttrs
	var stateFlags uint32
	for _, s := range states {
		stateFlags |= uint32(s)
	}
	length := 4
	mask := make([]byte, length)
	binary.NativeEndian.PutUint32(mask, stateFlags)
	value := make([]byte, length)
	binary.NativeEndian.PutUint32(value, 0)
	exprs = appendExpr(exprs,
		&nftnl.CtAttrs{
			DReg: 1,
			Key:  unix.NFT_CT_STATE,
		},
		&nftnl.BitwiseAttrs{
			SReg: 1,
			DReg: 1,
			Len:  uint32(length),
			Mask: &nftnl.DataAttrs{
				Value: mask,
			},
			Xor: &nftnl.DataAttrs{
				Value: value,
			},
		},
		&nftnl.CmpAttrs{
			SReg: 1,
			Op:   unix.NFT_CMP_NEQ,
			Data: &nftnl.DataAttrs{
				Value: make([]byte, length),
			},
		},
	)

	return exprs
}

func ctStateExprLegacy(states []uint32) []nftnl.ExprAttrs {
	var exprs []nftnl.ExprAttrs
	for _, s := range states {
		value := make([]byte, 4)
		binary.NativeEndian.PutUint32(value, s)
		exprs = appendExpr(exprs,
			&nftnl.CtAttrs{
				DReg: 1,
				Key:  unix.NFT_CT_STATE,
			},
			&nftnl.CmpAttrs{
				SReg: 1,
				Op:   unix.NFT_CMP_EQ,
				Data: &nftnl.DataAttrs{
					Value: value,
				},
			},
		)
	}
	return exprs
}

// TODO: Double check if this is correct
func ctStatesFromExpr(attr *nftnl.BitwiseAttrs) []uint32 {
	var states []uint32
	if attr.Mask == nil || len(attr.Mask.Value) < 4 {
		return states
	}
	stateFlags := binary.NativeEndian.Uint32(attr.Mask.Value)
	for i := uint32(0); i < 32; i++ {
		if (stateFlags & (1 << i)) != 0 {
			states = append(states, 1<<i)
		}
	}
	return states
}

func portExpr(port uint16) []nftnl.ExprAttrs {
	var exprs []nftnl.ExprAttrs

	value := make([]byte, 2)
	binary.BigEndian.PutUint16(value, port)

	exprs = appendExpr(exprs,
		&nftnl.PayloadAttrs{
			DReg:   1,
			Base:   unix.NFT_PAYLOAD_TRANSPORT_HEADER,
			Offset: 0, // TCP/UDP source/dest port offset
			Len:    2,
		},
		&nftnl.CmpAttrs{
			SReg: 1,
			Op:   unix.NFT_CMP_EQ,
			Data: &nftnl.DataAttrs{
				Value: value,
			},
		},
	)

	return exprs
}

func portFromExpr(attr *nftnl.CmpAttrs) uint16 {
	if attr.Data == nil || len(attr.Data.Value) < 2 {
		return 0
	}
	return binary.BigEndian.Uint16(attr.Data.Value)
}

func ctPortExpr(port uint16) []nftnl.ExprAttrs {
	var exprs []nftnl.ExprAttrs

	value := make([]byte, 2)
	binary.NativeEndian.PutUint16(value, port)

	exprs = appendExpr(exprs,
		&nftnl.MetaAttrs{
			DReg: 1,
			Key:  unix.NFT_CT_PROTO_SRC,
		},
		&nftnl.CmpAttrs{
			SReg: 1,
			Op:   unix.NFT_CMP_EQ,
			Data: &nftnl.DataAttrs{
				Value: value,
			},
		},
	)

	return exprs
}

func ctPortFromExpr(attr *nftnl.CmpAttrs) uint16 {
	if attr.Data == nil || len(attr.Data.Value) < 2 {
		return 0
	}
	return binary.NativeEndian.Uint16(attr.Data.Value)
}

func ctPrefixExpr(prefix *netip.Prefix, isSrc bool) []nftnl.ExprAttrs {
	var exprs []nftnl.ExprAttrs
	addr := prefix.Addr()
	var base uint32

	if addr.Is4() && isSrc {
		base = unix.NFT_CT_SRC_IP
	} else if addr.Is4() && !isSrc {
		base = unix.NFT_CT_DST_IP
	} else if addr.Is6() && isSrc {
		base = unix.NFT_CT_SRC_IP6
	} else {
		base = unix.NFT_CT_DST_IP6
	}

	var offset uint32 = 12 // IPv4 src/dst offset
	if addr.Is6() {
		offset = 8 // IPv6 src/dst offset
	}
	if !isSrc {
		offset += uint32(len(addr.AsSlice()))
	}
	length := uint32(len(addr.AsSlice()))
	// Big endian ?
	mask := net.CIDRMask(prefix.Bits(), addr.BitLen())

	exprs = appendExpr(exprs,
		&nftnl.PayloadAttrs{
			DReg:   1,
			Base:   base,
			Offset: offset,
			Len:    length,
		},
		&nftnl.BitwiseAttrs{
			SReg: 1,
			Len:  length,
			Mask: &nftnl.DataAttrs{
				Value: mask,
			},
			Xor: &nftnl.DataAttrs{
				Value: make([]byte, length),
			},
		},
	)

	return exprs
}

func ctPrefixFromExpr(attr *nftnl.BitwiseAttrs) *netip.Prefix {
	if attr.Mask == nil {
		return nil
	}
	prefixLen := 0
	for _, b := range attr.Mask.Value {
		for i := 7; i >= 0; i-- {
			if (b & (1 << i)) != 0 {
				prefixLen++
			} else {
				break
			}
		}
	}
	var addr netip.Addr
	if len(attr.Mask.Value) == net.IPv4len {
		addr = netip.AddrFrom4([4]byte{})
	} else if len(attr.Mask.Value) == net.IPv6len {
		addr = netip.AddrFrom16([16]byte{})
	} else {
		return nil
	}
	prefix := netip.PrefixFrom(addr, prefixLen)
	return &prefix
}
