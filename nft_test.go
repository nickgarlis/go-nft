package nft_test

import (
	"net/netip"
	"runtime"
	"testing"

	"github.com/nickgarlis/go-nft"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

func OpenSystemConn(t *testing.T) (*nft.Conn, func()) {
	t.Helper()
	runtime.LockOSThread()
	netns, err := netns.New()
	if err != nil {
		t.Fatalf("failed to get current network namespace: %v", err)
	}
	conn, err := nft.Open(&nft.Config{
		NetNS: int(netns),
	})
	if err != nil {
		t.Fatalf("failed to create nftables connection: %v", err)
	}
	b := nft.NewBatch()
	b.FlushRuleset()
	if err := conn.SendBatch(b); err != nil {
		t.Fatalf("failed to flush ruleset during setup: %v", err)
	}
	closer := func() {
		b := nft.NewBatch()
		b.FlushRuleset()
		if err := conn.SendBatch(b); err != nil {
			t.Fatalf("failed to flush ruleset during cleanup: %v", err)
		}
		defer runtime.UnlockOSThread()
		connCloseErr := conn.Close()
		netnsCloseErr := netns.Close()
		if connCloseErr != nil {
			t.Fatalf("failed to close nftables connection: %v", connCloseErr)
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

	tableName := "test-table"

	batch := nft.NewBatch()
	if err := batch.NewTable(&nft.Table{
		Family: unix.NFPROTO_IPV4,
		Name:   tableName,
	}); err != nil {
		t.Fatalf("failed to add NewTable to batch: %v", err)
	}
	if err := conn.SendBatch(batch); err != nil {
		t.Fatalf("failed to create table: %v", err)
	}

	table, err := conn.GetTable(&nft.Table{
		Family: unix.NFPROTO_IPV4,
		Name:   tableName,
	})
	if err != nil {
		t.Fatalf("failed to get table: %v", err)
	}
	if table == nil {
		t.Fatal("expected table to be non-nil after creation")
	}
	if table.Name != tableName {
		t.Fatalf("expected table name to be '%s', got '%s'", tableName, table.Name)
	}
}

func TestGetTables(t *testing.T) {
	conn, closer := OpenSystemConn(t)
	defer closer()

	want := []string{
		"test-table-0",
		"test-table-1",
		"test-table-2",
	}

	batch := nft.NewBatch()
	for _, wantTable := range want {
		if err := batch.NewTable(&nft.Table{
			Family: unix.NFPROTO_IPV4,
			Name:   wantTable,
		}); err != nil {
			t.Fatalf("failed to add NewTable to batch: %v", err)
		}
	}

	if err := conn.SendBatch(batch); err != nil {
		t.Fatalf("failed to create tables: %v", err)
	}

	got, err := conn.GetTables(unix.NFPROTO_IPV4)
	if err != nil {
		t.Fatalf("failed to get tables: %v", err)
	}
	if len(got) < len(want) {
		t.Fatalf("expected at least 3 tables, got %d", len(got))
	}

	found := make(map[string]bool)
	for _, gotTable := range got {
		found[gotTable.Name] = true
	}

	for _, wantTable := range want {
		if !found[wantTable] {
			t.Errorf("expected to find table '%s', but it was missing", wantTable)
		}
	}
}

func TestDelTable(t *testing.T) {
	conn, closer := OpenSystemConn(t)
	defer closer()

	tables := []string{
		"test-table-0",
		"test-table-1",
		"test-table-2",
	}

	batch := nft.NewBatch()
	for _, table := range tables {
		if err := batch.NewTable(&nft.Table{
			Family: unix.NFPROTO_IPV4,
			Name:   table,
		}); err != nil {
			t.Fatalf("failed to add NewTable to batch: %v", err)
		}
	}

	if err := conn.SendBatch(batch); err != nil {
		t.Fatalf("failed to create tables: %v", err)
	}

	batch.Clear()
	if err := batch.DelTable(&nft.Table{
		Family: unix.NFPROTO_IPV4,
		Name:   tables[1],
	}); err != nil {
		t.Fatalf("failed to add DelTable to batch: %v", err)
	}
	if err := conn.SendBatch(batch); err != nil {
		t.Fatalf("failed to create tables: %v", err)
	}

	got, err := conn.GetTables(unix.NFPROTO_IPV4)
	if err != nil {
		t.Fatalf("failed to get tables: %v", err)
	}
	if len(got) != len(tables)-1 {
		t.Fatalf("expected 2 tables, got %d", len(got))
	}

	for _, gotTable := range got {
		if gotTable.Name == tables[1] {
			t.Fatalf("expected '%s' to be deleted, but it still exists", tables[1])
		}
	}
}

func TestCreateChain(t *testing.T) {
	conn, closer := OpenSystemConn(t)
	defer closer()

	tableName := "test-table"
	chainName := "test-chain"

	batch := nft.NewBatch()
	if err := batch.NewTable(&nft.Table{
		Family: unix.NFPROTO_IPV4,
		Name:   tableName,
	}); err != nil {
		t.Fatalf("failed to add NewTable to batch: %v", err)
	}
	if err := batch.NewChain(&nft.Chain{
		Family: unix.NFPROTO_IPV4,
		Table:  tableName,
		Name:   chainName,
	}); err != nil {
		t.Fatalf("failed to add NewChain to batch: %v", err)
	}
	if err := conn.SendBatch(batch); err != nil {
		t.Fatalf("failed to create table and chain: %v", err)
	}

	chain, err := conn.GetChain(&nft.Chain{
		Family: unix.NFPROTO_IPV4,
		Table:  tableName,
		Name:   chainName,
	})
	if err != nil {
		t.Fatalf("failed to get chain: %v", err)
	}
	if chain == nil {
		t.Fatal("expected chain to be non-nil after creation")
	}
	if chain.Name != chainName {
		t.Fatalf("expected chain name to be '%s', got '%s'", chainName, chain.Name)
	}
}

func TestFlushRuleset(t *testing.T) {
	conn, closer := OpenSystemConn(t)
	defer closer()

	tables := []string{
		"test-table-0",
		"test-table-1",
		"test-table-2",
	}

	batch := nft.NewBatch()
	for _, wantTable := range tables {
		batch.NewTable(&nft.Table{
			Family: unix.NFPROTO_IPV4,
			Name:   wantTable,
		})
	}

	if err := conn.SendBatch(batch); err != nil {
		t.Fatalf("failed to create tables: %v", err)
	}

	batch.Clear()
	batch.FlushRuleset()
	if err := conn.SendBatch(batch); err != nil {
		t.Fatalf("failed to flush ruleset: %v", err)
	}

	got, err := conn.GetTables(unix.NFPROTO_IPV4)
	if err != nil {
		t.Fatalf("failed to get tables: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected 0 tables after flush, got %d", len(got))
	}
}

func TestRule(t *testing.T) {
	conn, closer := OpenSystemConn(t)
	defer closer()

	tableName := "test-table"
	chainName := "test-chain"

	batch := nft.NewBatch()
	err := batch.NewTable(&nft.Table{
		Family: unix.NFPROTO_INET,
		Name:   tableName,
	})

	assert.NoError(t, err, "failed to add NewTable to batch")
	batch.NewChain(&nft.Chain{
		Family: unix.NFPROTO_INET,
		Table:  tableName,
		Name:   chainName,
	})
	assert.NoError(t, err, "failed to add NewChain to batch")

	prefix := netip.MustParsePrefix("1.1.1.1/24")
	addr := netip.MustParseAddr("2.2.2.2")

	want := &nft.Rule{
		Family:  unix.NFPROTO_INET,
		Table:   tableName,
		Chain:   chainName,
		IIface:  "lo",
		L3Proto: unix.NFPROTO_IPV4,
		SrcIPv4: &nft.IPMatch{
			Addr:   &addr,
			Prefix: &prefix,
		},
		L4Proto: unix.IPPROTO_TCP,
		SrcPort: &nft.PortMatch{
			Port: 80,
		},
		Ct: &nft.CtMatch{
			States: []nft.CtState{nft.CtStateNew, nft.CtStateEstablished},
		},
		Counter: &nft.Counter{
			Bytes:   2,
			Packets: 2,
		},
		Action: &nft.Action{
			Verdict: &nft.Verdict{
				Code: nft.VerdictCodeAccept,
			},
		},
	}

	err = batch.NewRule(want)

	assert.NoError(t, err, "failed to add NewRule to batch")

	err = conn.SendBatch(batch)
	assert.NoError(t, err, "failed to create table and chain")

	rules, err := conn.GetRules(&nft.Chain{
		Family: unix.NFPROTO_INET,
		Table:  tableName,
		Name:   chainName,
	})
	assert.NoError(t, err, "failed to get rules")
	assert.Len(t, rules, 1, "expected exactly one rule")

	got := rules[0]

	assert.Equal(t, want.SrcIPv4.Prefix, got.SrcIPv4.Prefix, "expected source IPv4 prefix to match")

	// Ignore auto-assigned fields
	want.Handle = got.Handle
	want.ID = got.ID
	require.Equal(t, want, got, "expected retrieved rule to match created rule")
}
