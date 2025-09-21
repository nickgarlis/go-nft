package nftnl_test

import (
	"flag"
	"runtime"
	"testing"

	"github.com/mdlayher/netlink"
	"github.com/nickgarlis/go-nft/nftnl"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

var itests = flag.Bool("integration_tests", false, "Run tests that operate against the live kernel")

func OpenSystemConn(t *testing.T) (*nftnl.Conn, func()) {
	t.Helper()
	if !*itests {
		t.SkipNow()
	}
	runtime.LockOSThread()
	netns, err := netns.New()
	if err != nil {
		t.Fatalf("failed to get current network namespace: %v", err)
	}
	conn, err := nftnl.Open(&nftnl.Config{
		NetNS: int(netns),
	})
	if err != nil {
		t.Fatalf("failed to create nftnl connection: %v", err)
	}
	batch := nftnl.NewBatch()
	batch.Add(nftnl.Msg{
		Header: nftnl.Header{
			SubsysID: unix.NFNL_SUBSYS_NFTABLES,
			MsgType:  unix.NFT_MSG_DELTABLE,
			Flags:    netlink.Request | netlink.Acknowledge,
		},
		NfGenMsg: nftnl.NfGenMsg{
			Family: unix.NFPROTO_UNSPEC,
		},
	})
	if err := conn.SendBatch(batch); err != nil {
		t.Fatalf("failed to flush ruleset during setup: %v", err)
	}
	closer := func() {
		defer runtime.UnlockOSThread()

		batch := nftnl.NewBatch()
		batch.Add(nftnl.Msg{
			Header: nftnl.Header{
				SubsysID: unix.NFNL_SUBSYS_NFTABLES,
				MsgType:  unix.NFT_MSG_DELTABLE,
				Flags:    netlink.Request | netlink.Acknowledge,
			},
			NfGenMsg: nftnl.NfGenMsg{
				Family: unix.NFPROTO_UNSPEC,
			},
		})
		if err := conn.SendBatch(batch); err != nil {
			t.Fatalf("failed to flush ruleset during setup: %v", err)
		}
		connCloseErr := conn.Close()
		netnsCloseErr := netns.Close()
		if connCloseErr != nil {
			t.Fatalf("failed to close nftnl connection: %v", connCloseErr)
		}
		if netnsCloseErr != nil {
			t.Fatalf("failed to close network namespace handle: %v", netnsCloseErr)
		}
	}
	return conn, closer
}

func TestCreateTable(t *testing.T) {
	conn, closer := OpenSystemConn(t)
	defer closer()

	batch := nftnl.NewBatch()
	batch.Add(nftnl.Msg{
		Header: nftnl.Header{
			SubsysID: unix.NFNL_SUBSYS_NFTABLES,
			MsgType:  unix.NFT_MSG_NEWTABLE,
			Flags:    netlink.Request | netlink.Acknowledge | netlink.Create | netlink.Excl,
		},
		NfGenMsg: nftnl.NfGenMsg{
			Family: unix.NFPROTO_IPV4,
		},
		Attrs: &nftnl.TableAttrs{
			Name: "test-table",
		},
	})
	if err := conn.SendBatch(batch); err != nil {
		t.Fatalf("failed to create table: %v", err)
	}

	msgs, err := conn.Send(nftnl.Msg{
		Header: nftnl.Header{
			SubsysID: unix.NFNL_SUBSYS_NFTABLES,
			MsgType:  unix.NFT_MSG_GETTABLE,
			Flags:    netlink.Request | netlink.Dump,
		},
		NfGenMsg: nftnl.NfGenMsg{
			Family: unix.NFPROTO_IPV4,
		},
	})
	if err != nil {
		t.Fatalf("failed to get tables: %v", err)
	}

	if len(msgs) != 1 {
		t.Fatalf("expected 1 table, got %d", len(msgs))
	}

	table, ok := msgs[0].Attrs.(*nftnl.TableAttrs)
	if !ok {
		t.Fatalf("expected TableAttrs, got %T", msgs[0].Attrs)
	}
	if table.Name != "test-table" {
		t.Fatalf("expected table name to be 'test-table', got '%s'", table.Name)
	}
}
