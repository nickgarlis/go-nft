package nft

import (
	"sync"

	"github.com/mdlayher/netlink"
	"github.com/nickgarlis/go-nft/nftnl"
	"golang.org/x/sys/unix"
)

type Batch struct {
	nftnlBatch *nftnl.Batch
	mu         sync.Mutex
	lastID     uint32
}

func NewBatch() *Batch {
	return &Batch{nftnlBatch: nftnl.NewBatch()}
}

// newID generates a new unique ID for use in batch operations.
// To be used internally under lock.
func (b *Batch) newID() uint32 {
	b.lastID++
	return b.lastID
}

// NewID generates a new unique ID for use in batch operations.
func (b *Batch) NewID() uint32 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.newID()
}

func (b *Batch) FlushRuleset() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.nftnlBatch.Add(nftnl.Msg{
		Header: nftnl.Header{
			SubsysID: unix.NFNL_SUBSYS_NFTABLES,
			MsgType:  unix.NFT_MSG_DELTABLE,
			Flags:    netlink.Request | netlink.Acknowledge,
		},
		NfGenMsg: nftnl.NfGenMsg{
			Family: unix.NFPROTO_UNSPEC,
		},
	})
}

func (b *Batch) Add(msg nftnl.Msg) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.nftnlBatch.Add(msg)
}

func (b *Batch) Clear() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.nftnlBatch.Clear()
}
