package nft

import (
	"fmt"
	"net/netip"

	"github.com/mdlayher/netlink"
	"github.com/nickgarlis/go-nft/nftnl"
	"golang.org/x/sys/unix"
)

type IPMatch struct {
	Addr   *netip.Addr
	Prefix *netip.Prefix
	Set    string
	SetID  uint32
}

type PortMatch struct {
	Port  uint16
	Set   string
	SetID uint32
}

type CtMatch struct {
	SrcIPv4 *IPMatch
	DstIPv4 *IPMatch
	SrcIPv6 *IPMatch
	DstIPv6 *IPMatch
	SrcPort *PortMatch
	DstPort *PortMatch
	States  []CtState
}

type Counter struct {
	Bytes   uint64
	Packets uint64
}

type Quota struct {
	Bytes uint64
}

type Verdict struct {
	Code    VerdictCode
	Chain   string
	ChainID uint32
}

type Action struct {
	Verdict *Verdict
}

type Rule struct {
	Family  uint8
	ID      uint32
	Table   string
	Chain   string
	ChainID uint32
	Handle  uint64
	L3Proto uint8
	L4Proto uint8
	IIface  string
	OIface  string
	SrcIPv4 *IPMatch
	DstIPv4 *IPMatch
	SrcIPv6 *IPMatch
	DstIPv6 *IPMatch
	SrcPort *PortMatch
	DstPort *PortMatch
	Ct      *CtMatch
	Counter *Counter
	Quota   *Quota
	Action  *Action
}

func (r *Rule) validateCreate() error {
	if r.Table == "" {
		return fmt.Errorf("table name must be specified")
	}
	if r.Chain == "" && r.ChainID == 0 {
		return fmt.Errorf("chain name or ID must be specified")
	}
	if r.Family == 0 {
		return fmt.Errorf("family must be specified")
	}
	if r.Family == unix.NFPROTO_INET {
		if r.L3Proto == 0 &&
			(r.SrcIPv4 != nil || r.DstIPv4 != nil || r.SrcIPv6 != nil || r.DstIPv6 != nil) {
			return fmt.Errorf("L3 protocol must be specified for inet family when matching on IP addresses")
		}

		if r.L3Proto == unix.NFPROTO_IPV4 && (r.SrcIPv6 != nil || r.DstIPv6 != nil) {
			return fmt.Errorf("cannot match on IPv6 addresses when L3 protocol is IPv4")
		}

		if r.L3Proto == unix.NFPROTO_IPV6 && (r.SrcIPv4 != nil || r.DstIPv4 != nil) {
			return fmt.Errorf("cannot match on IPv4 addresses when L3 protocol is IPv6")
		}
	}

	return nil
}

func (r *Rule) marshal() *nftnl.RuleAttrs {
	return &nftnl.RuleAttrs{
		Table:       r.Table,
		Chain:       r.Chain,
		ID:          r.ID,
		Handle:      r.Handle,
		ChainID:     r.ChainID,
		Expressions: r.marshalExprs(),
	}
}

func (r *Rule) unmarshal(family uint8, attrs *nftnl.RuleAttrs) {
	r.Family = family
	r.Table = attrs.Table
	r.Chain = attrs.Chain
	r.ID = attrs.ID
	r.Handle = attrs.Handle
	r.ChainID = attrs.ChainID

	r.unmarshalPrefixExprs(attrs)
}

func (c *Conn) getRules(family uint8, table string, chain string, handle uint64) ([]*Rule, error) {
	flags := netlink.Request
	if handle == 0 {
		flags |= netlink.Dump
	}
	msg := nftnl.Msg{
		Header: nftnl.Header{
			SubsysID: unix.NFNL_SUBSYS_NFTABLES,
			MsgType:  unix.NFT_MSG_GETRULE,
			Flags:    flags,
		},
		NfGenMsg: nftnl.NfGenMsg{
			Family: family,
		},
		Attrs: &nftnl.RuleAttrs{
			Table: table,
			Chain: chain,
		},
	}

	res, err := c.nftnlConn.Send(msg)
	if err != nil {
		return nil, err
	}

	attrs, err := extractAttrs[*nftnl.RuleAttrs](res)
	if err != nil {
		return nil, err
	}

	rules := make([]*Rule, len(attrs))
	for i, a := range attrs {
		r := &Rule{}
		r.unmarshal(family, a)
		rules[i] = r
	}
	return rules, nil
}

func (c *Conn) GetRules(chain *Chain) ([]*Rule, error) {
	return c.getRules(chain.Family, chain.Table, chain.Name, 0)
}

func (c *Conn) GetRule(rule *Rule) (*Rule, error) {
	if rule.Table == "" || rule.Chain == "" {
		return nil, fmt.Errorf("table and chain names must be specified")
	}
	if rule.ID == 0 || rule.Handle == 0 {
		return nil, fmt.Errorf("rule ID or handle must be specified")
	}

	rules, err := c.getRules(rule.Family, rule.Table, rule.Chain, rule.Handle)
	if err != nil {
		return nil, err
	}

	if len(rules) != 1 {
		return nil, fmt.Errorf("expected 1 rule, got %d", len(rules))
	}

	return rules[0], nil
}

func (b *Batch) NewRule(rule *Rule) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := rule.validateCreate(); err != nil {
		return err
	}
	rule.ID = b.newID()
	b.nftnlBatch.Add(nftnl.Msg{
		Header: nftnl.Header{
			SubsysID: unix.NFNL_SUBSYS_NFTABLES,
			MsgType:  unix.NFT_MSG_NEWRULE,
			Flags:    netlink.Request | netlink.Acknowledge | netlink.Create,
		},
		NfGenMsg: nftnl.NfGenMsg{
			Family: rule.Family,
		},
		Attrs: rule.marshal(),
	})
	return nil
}

func (b *Batch) DelRule(rule *Rule) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if rule.Table == "" || rule.Chain == "" {
		return fmt.Errorf("table and chain names must be specified")
	}
	if rule.ID == 0 && rule.Handle == 0 {
		return fmt.Errorf("rule ID or handle must be specified")
	}
	b.nftnlBatch.Add(nftnl.Msg{
		Header: nftnl.Header{
			SubsysID: unix.NFNL_SUBSYS_NFTABLES,
			MsgType:  unix.NFT_MSG_DELRULE,
			Flags:    netlink.Request | netlink.Acknowledge,
		},
		NfGenMsg: nftnl.NfGenMsg{
			Family: rule.Family,
		},
		Attrs: rule.marshal(),
	})
	return nil
}
