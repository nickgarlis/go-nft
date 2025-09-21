package nft

import (
	"fmt"

	"github.com/mdlayher/netlink"
	"github.com/nickgarlis/go-nft/nftnl"
	"golang.org/x/sys/unix"
)

type Chain struct {
	Family uint8
	Table  string
	Name   string
	ID     uint32
}

func (c *Chain) marshal() *nftnl.ChainAttrs {
	return &nftnl.ChainAttrs{
		Table: c.Table,
		Name:  c.Name,
		ID:    c.ID,
	}
}

func (c *Chain) unmarshal(family uint8, attrs *nftnl.ChainAttrs) {
	c.Family = family
	c.Table = attrs.Table
	c.Name = attrs.Name
	c.ID = attrs.ID
}

func (c *Conn) getChains(family uint8, table string, chain string) ([]*Chain, error) {
	flags := netlink.Request
	if chain == "" {
		flags |= netlink.Dump
	}
	msg := nftnl.Msg{
		Header: nftnl.Header{
			SubsysID: unix.NFNL_SUBSYS_NFTABLES,
			MsgType:  unix.NFT_MSG_GETCHAIN,
			Flags:    flags,
		},
		NfGenMsg: nftnl.NfGenMsg{
			Family: family,
		},
		Attrs: &nftnl.ChainAttrs{
			Table: table,
			Name:  chain,
		},
	}

	res, err := c.nftnlConn.Send(msg)
	if err != nil {
		return nil, err
	}

	attrs, err := extractAttrs[*nftnl.ChainAttrs](res)
	if err != nil {
		return nil, err
	}

	chains := make([]*Chain, len(attrs))
	for i, a := range attrs {
		ch := &Chain{}
		ch.unmarshal(family, a)
		chains[i] = ch
	}
	return chains, nil
}

func (c *Conn) GetChains(table *Table) ([]*Chain, error) {
	if table.Name == "" {
		return nil, fmt.Errorf("table name must be specified")
	}
	return c.getChains(table.Family, table.Name, "")
}

func (c *Conn) GetChain(chain *Chain) (*Chain, error) {
	if chain.Table == "" || chain.Name == "" {
		return nil, fmt.Errorf("table and chain names must be specified")
	}
	chains, err := c.getChains(chain.Family, chain.Table, chain.Name)
	if err != nil {
		return nil, err
	}
	if len(chains) == 0 {
		return nil, fmt.Errorf("chain %q not found in table %q", chain.Name, chain.Table)
	}
	if len(chains) > 1 {
		return nil, fmt.Errorf("multiple chains found with name %q in table %q", chain.Name, chain.Table)
	}

	return chains[0], nil
}

func (b *Batch) NewChain(chain *Chain) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if chain.Table == "" || chain.Name == "" {
		return fmt.Errorf("table and chain names must be specified")
	}
	chain.ID = b.newID()
	b.nftnlBatch.Add(nftnl.Msg{
		Header: nftnl.Header{
			SubsysID: unix.NFNL_SUBSYS_NFTABLES,
			MsgType:  unix.NFT_MSG_NEWCHAIN,
			Flags:    netlink.Request | netlink.Acknowledge | netlink.Create,
		},
		NfGenMsg: nftnl.NfGenMsg{
			Family: chain.Family,
		},
		Attrs: chain.marshal(),
	})
	return nil
}

func (b *Batch) DelChain(chain *Chain) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if chain.Table == "" || chain.Name == "" {
		return fmt.Errorf("table and chain names must be specified")
	}
	b.nftnlBatch.Add(nftnl.Msg{
		Header: nftnl.Header{
			SubsysID: unix.NFNL_SUBSYS_NFTABLES,
			MsgType:  unix.NFT_MSG_DELCHAIN,
			Flags:    netlink.Request | netlink.Acknowledge | netlink.Excl,
		},
		NfGenMsg: nftnl.NfGenMsg{
			Family: chain.Family,
		},
		Attrs: chain.marshal(),
	})
	return nil
}
