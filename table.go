package nft

import (
	"fmt"

	"github.com/mdlayher/netlink"
	"github.com/nickgarlis/go-nft/nftnl"
	"golang.org/x/sys/unix"
)

type Table struct {
	Family uint8
	Name   string
}

func (t *Table) marshal() *nftnl.TableAttrs {
	return &nftnl.TableAttrs{
		Name: t.Name,
	}
}

func (t *Table) unmarshal(family uint8, attrs *nftnl.TableAttrs) {
	t.Family = family
	t.Name = attrs.Name
}

func (c *Conn) getTables(family uint8, name string) ([]*Table, error) {
	flags := netlink.Request
	if name == "" {
		flags |= netlink.Dump
	}
	msg := nftnl.Msg{
		Header: nftnl.Header{
			SubsysID: unix.NFNL_SUBSYS_NFTABLES,
			MsgType:  unix.NFT_MSG_GETTABLE,
			Flags:    flags,
		},
		NfGenMsg: nftnl.NfGenMsg{
			Family: family,
		},
		Attrs: &nftnl.TableAttrs{
			Name: name,
		},
	}

	nlMsg, err := c.nftnlConn.Send(msg)
	if err != nil {
		return nil, err
	}

	attrs, err := extractAttrs[*nftnl.TableAttrs](nlMsg)
	if err != nil {
		return nil, err
	}

	tables := make([]*Table, len(attrs))
	for i, a := range attrs {
		t := &Table{}
		t.unmarshal(family, a)
		tables[i] = t
	}
	return tables, nil
}

func (c *Conn) GetTables(family uint8) ([]*Table, error) {
	return c.getTables(family, "")
}

func (c *Conn) GetTable(table *Table) (*Table, error) {
	if table.Name == "" {
		return nil, fmt.Errorf("table name must be specified")
	}
	tables, err := c.getTables(table.Family, table.Name)
	if err != nil {
		return nil, err
	}
	if len(tables) == 0 {
		return nil, fmt.Errorf("table %q not found", table.Name)
	}
	if len(tables) > 1 {
		return nil, fmt.Errorf("multiple tables found with name %q", table.Name)
	}

	return tables[0], nil
}

func (b *Batch) NewTable(table *Table) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if table.Name == "" {
		return fmt.Errorf("table name must be specified")
	}
	attrs := table.marshal()
	b.nftnlBatch.Add(nftnl.Msg{
		Header: nftnl.Header{
			SubsysID: unix.NFNL_SUBSYS_NFTABLES,
			MsgType:  unix.NFT_MSG_NEWTABLE,
			Flags:    netlink.Request | netlink.Acknowledge | netlink.Create,
		},
		NfGenMsg: nftnl.NfGenMsg{
			Family: table.Family,
		},
		Attrs: attrs,
	})
	return nil
}

func (b *Batch) DelTable(table *Table) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if table.Name == "" {
		return fmt.Errorf("table name must be specified")
	}
	b.nftnlBatch.Add(nftnl.Msg{
		Header: nftnl.Header{
			SubsysID: unix.NFNL_SUBSYS_NFTABLES,
			MsgType:  unix.NFT_MSG_DELTABLE,
			Flags:    netlink.Request | netlink.Acknowledge | netlink.Excl,
		},
		NfGenMsg: nftnl.NfGenMsg{
			Family: table.Family,
		},
		Attrs: table.marshal(),
	})
	return nil
}

func (b *Batch) FlushTable(table *Table) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if table.Name == "" {
		return fmt.Errorf("table name must be specified")
	}
	b.nftnlBatch.Add(nftnl.Msg{
		Header: nftnl.Header{
			SubsysID: unix.NFNL_SUBSYS_NFTABLES,
			MsgType:  unix.NFT_MSG_DELRULE,
			Flags:    netlink.Request | netlink.Acknowledge,
		},
		NfGenMsg: nftnl.NfGenMsg{
			Family: table.Family,
		},
		Attrs: &nftnl.RuleAttrs{
			Table: table.Name,
		},
	})
	return nil
}
