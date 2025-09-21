package nft

import (
	"net"
	"net/netip"

	"github.com/nickgarlis/go-nft/nftnl"
	"golang.org/x/sys/unix"
)

func (r *Rule) marshalExprs() []nftnl.ExprAttrs {
	exprs := []nftnl.ExprAttrs{}

	if r.IIface != "" {
		exprs = appendExpr(exprs,
			&nftnl.MetaAttrs{
				DReg: 1,
				Key:  unix.NFT_META_IIFNAME,
			},
			&nftnl.CmpAttrs{
				Op:   unix.NFT_CMP_EQ,
				SReg: 1,
				Data: &nftnl.DataAttrs{
					Value: []byte(r.IIface + "\x00"),
				},
			},
		)
	}

	if r.OIface != "" {
		exprs = appendExpr(exprs,
			&nftnl.MetaAttrs{
				DReg: 1,
				Key:  unix.NFT_META_OIFNAME,
			},
			&nftnl.CmpAttrs{
				Op:   unix.NFT_CMP_EQ,
				SReg: 1,
				Data: &nftnl.DataAttrs{
					Value: []byte(r.OIface + "\x00"),
				},
			},
		)
	}

	if r.L3Proto != 0 {
		exprs = appendExpr(exprs,
			&nftnl.MetaAttrs{
				DReg: 1,
				Key:  unix.NFT_META_NFPROTO,
			},
			&nftnl.CmpAttrs{
				Op:   unix.NFT_CMP_EQ,
				SReg: 1,
				Data: &nftnl.DataAttrs{
					Value: []byte{r.L3Proto},
				},
			},
		)
	}

	if r.SrcIPv4 != nil {
		if r.SrcIPv4.Prefix != nil {
			exprs = append(exprs, prefixExpr(r.SrcIPv4.Prefix, true)...)
		} else if r.SrcIPv4.Addr != nil {
			exprs = append(exprs, addrExpr(r.SrcIPv4.Addr, true)...)
		}
	}

	if r.DstIPv4 != nil {
		if r.DstIPv4.Prefix != nil {
			exprs = append(exprs, prefixExpr(r.DstIPv4.Prefix, false)...)
		} else if r.DstIPv4.Addr != nil {
			exprs = append(exprs, addrExpr(r.DstIPv4.Addr, false)...)
		}
	}

	if r.SrcIPv6 != nil {
		if r.SrcIPv6.Prefix != nil {
			exprs = append(exprs, prefixExpr(r.SrcIPv6.Prefix, true)...)
		} else if r.SrcIPv6.Addr != nil {
			exprs = append(exprs, addrExpr(r.SrcIPv6.Addr, true)...)
		}
	}

	if r.DstIPv6 != nil {
		if r.DstIPv6.Prefix != nil {
			exprs = append(exprs, prefixExpr(r.DstIPv6.Prefix, false)...)
		} else if r.DstIPv6.Addr != nil {
			exprs = append(exprs, addrExpr(r.DstIPv6.Addr, false)...)
		}
	}

	if r.L4Proto != 0 {
		exprs = appendExpr(exprs,
			&nftnl.MetaAttrs{
				DReg: 1,
				Key:  unix.NFT_META_L4PROTO,
			},
			&nftnl.CmpAttrs{
				Op:   unix.NFT_CMP_EQ,
				SReg: 1,
				Data: &nftnl.DataAttrs{
					Value: []byte{r.L4Proto},
				},
			},
		)
	}

	if r.SrcPort != nil {
		if r.SrcPort.Port != 0 {
			exprs = append(exprs, portExpr(r.SrcPort.Port)...)
		}
	}

	if r.DstPort != nil {
		if r.DstPort.Port != 0 {
			exprs = append(exprs, portExpr(r.DstPort.Port)...)
		}
	}

	if r.Ct != nil {
		if r.Ct.SrcIPv4 != nil {
			if r.Ct.SrcIPv4.Prefix != nil {
				exprs = append(exprs, ctPrefixExpr(r.Ct.SrcIPv4.Prefix, true)...)
			}
		}

		if r.Ct.DstIPv4 != nil {
			if r.Ct.DstIPv4.Prefix != nil {
				exprs = append(exprs, ctPrefixExpr(r.Ct.DstIPv4.Prefix, false)...)
			}
		}

		if r.Ct.SrcIPv6 != nil {
			if r.Ct.SrcIPv6.Prefix != nil {
				exprs = append(exprs, ctPrefixExpr(r.Ct.SrcIPv6.Prefix, true)...)
			}
		}

		if r.Ct.DstIPv6 != nil {
			if r.Ct.DstIPv6.Prefix != nil {
				exprs = append(exprs, ctPrefixExpr(r.Ct.DstIPv6.Prefix, false)...)
			}
		}

		if r.Ct.SrcPort != nil {
			if r.Ct.SrcPort.Port != 0 {
				exprs = append(exprs, ctPortExpr(r.Ct.SrcPort.Port)...)
			}
		}
		if r.Ct.DstPort != nil {
			if r.Ct.DstPort.Port != 0 {
				exprs = append(exprs, ctPortExpr(r.Ct.DstPort.Port)...)
			}
		}
		if len(r.Ct.States) > 0 {
			exprs = append(exprs, ctStateExpr(r.Ct.States)...)
		}
	}

	if r.Counter != nil {
		exprs = appendExpr(exprs,
			&nftnl.CounterAttrs{
				Bytes:   r.Counter.Bytes,
				Packets: r.Counter.Packets,
			},
		)
	}

	if r.Quota != nil {
		exprs = appendExpr(exprs,
			&nftnl.QuotaAttrs{
				Bytes: r.Counter.Bytes,
			},
		)
	}

	if r.Action != nil {
		if r.Action.Verdict != nil {
			exprs = appendExpr(exprs,
				&nftnl.ImmediateAttrs{
					DReg: unix.NFT_REG_VERDICT,
					Data: &nftnl.VerdictAttrs{
						Code:    uint32(r.Action.Verdict.Code),
						Chain:   r.Action.Verdict.Chain,
						ChainID: r.Action.Verdict.ChainID,
					},
				},
			)
		}
	}
	return exprs
}

func appendExpr(slice []nftnl.ExprAttrs, data ...nftnl.ExprDataAttrs) []nftnl.ExprAttrs {
	exprs := make([]nftnl.ExprAttrs, len(data))
	for i, d := range data {
		exprs[i] = nftnl.ExprAttrs{
			Name: d.ExprName(),
			Data: d,
		}
	}
	return append(slice, exprs...)
}

func (r *Rule) unmarshalPrefixExprs(attrs *nftnl.RuleAttrs) {
	for i := 0; i < len(attrs.Expressions); i++ {
		expr := attrs.Expressions[i]

		var match *IPMatch

		switch e := expr.Data.(type) {
		case *nftnl.PayloadAttrs:
			if e.Base != unix.NFT_PAYLOAD_NETWORK_HEADER {
				continue
			}
			switch {
			case e.Offset == 12 && e.Len == 4:
				if r.SrcIPv4 == nil {
					r.SrcIPv4 = &IPMatch{}
				}
				match = r.SrcIPv4
			case e.Offset == 16 && e.Len == 4:
				if r.DstIPv4 == nil {
					r.DstIPv4 = &IPMatch{}
				}
				match = r.DstIPv4
			case e.Offset == 8 && e.Len == 16:
				if r.SrcIPv6 == nil {
					r.SrcIPv6 = &IPMatch{}
				}
				match = r.SrcIPv6
			case e.Offset == 24 && e.Len == 16:
				if r.DstIPv6 == nil {
					r.DstIPv6 = &IPMatch{}
				}
				match = r.DstIPv6
			default:
				continue
			}
		case *nftnl.CtAttrs:
			if r.Ct == nil {
				r.Ct = &CtMatch{}
			}
			switch e.Key {
			case unix.NFT_CT_SRC_IP:
				if r.Ct.SrcIPv4 == nil {
					r.Ct.SrcIPv4 = &IPMatch{}
				}
				match = r.Ct.SrcIPv4
			case unix.NFT_CT_DST_IP:
				if r.Ct.DstIPv4 == nil {
					r.Ct.DstIPv4 = &IPMatch{}
				}
				match = r.Ct.DstIPv4
			case unix.NFT_CT_SRC_IP6:
				if r.Ct.SrcIPv6 == nil {
					r.Ct.SrcIPv6 = &IPMatch{}
				}
				match = r.Ct.SrcIPv6
			case unix.NFT_CT_DST_IP6:
				if r.Ct.DstIPv6 == nil {
					r.Ct.DstIPv6 = &IPMatch{}
				}
				match = r.Ct.DstIPv6
			default:
				continue
			}
		default:
			continue
		}

		if match == nil {
			continue
		}

		if i+2 >= len(attrs.Expressions) {
			return
		}

		bitwise, ok := attrs.Expressions[i+1].Data.(*nftnl.BitwiseAttrs)
		if !ok {
			continue
		}

		cmp, ok := attrs.Expressions[i+2].Data.(*nftnl.CmpAttrs)
		if !ok {
			continue
		}

		if cmp.Data == nil || len(cmp.Data.Value) == 0 {
			continue
		}

		addr, ok := netip.AddrFromSlice(cmp.Data.Value)
		if !ok {
			continue
		}

		if bitwise.Mask == nil || len(bitwise.Mask.Value) == 0 {
			continue
		}

		mask := net.IPMask(bitwise.Mask.Value)

		prefixLen, _ := mask.Size()

		prefix := netip.PrefixFrom(addr, prefixLen)

		match.Prefix = &prefix

		i += 2
	}
}

// func (r *Rule) unmarshalCtStateExprs(attrs *nftnl.RuleAttrs) {
// 	for i := 0; i < len(attrs.Expressions); i++ {
// 		expr := attrs.Expressions[i]

// 		ct, ok := expr.Data.(*nftnl.CtAttrs)
// 		if !ok {
// 			continue
// 		}

// 		if ct.Key != unix.NFT_CT_STATE {
// 			continue
// 		}

// 		if r.Ct == nil {
// 			r.Ct = &CtMatch{}
// 		}

// 		if i+2 >= len(attrs.Expressions) {
// 			return
// 		}

// 		bitwise, ok := attrs.Expressions[i+1].Data.(*nftnl.BitwiseAttrs)
// 		if !ok {
// 			continue
// 		}

// 		cmp, ok := attrs.Expressions[i+2].Data.(*nftnl.CmpAttrs)
// 		if !ok {
// 			continue
// 		}

// 		if cmp.Data == nil || len(cmp.Data.Value) != 4 {
// 			continue
// 		}
// 	}
// }
