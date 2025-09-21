package nftnl

import (
	"sync"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

type Batch struct {
	mu       sync.Mutex
	messages []Msg
}

func NewBatch() *Batch {
	return &Batch{}
}

func (b *Batch) Add(msg Msg) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.messages = append(b.messages, msg)
}

func (b *Batch) Clear() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.messages = nil
}

func (b *Batch) Marshal() ([]Msg, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	batch := make([]Msg, len(b.messages)+2)
	batch[0] = Msg{
		Header: Header{
			SubsysID: unix.NFNL_MSG_BATCH_BEGIN,
			Flags:    netlink.Request,
		},
		NfGenMsg: NfGenMsg{
			Family: unix.NFPROTO_UNSPEC,
			ResID:  unix.NFNL_SUBSYS_NFTABLES,
		},
	}

	for i, msg := range b.messages {
		batch[i+1] = msg
	}

	batch[len(b.messages)+1] = Msg{
		Header: Header{
			SubsysID: unix.NFNL_MSG_BATCH_END,
			Flags:    netlink.Request,
		},
		NfGenMsg: NfGenMsg{
			Family: unix.NFPROTO_UNSPEC,
			ResID:  unix.NFNL_SUBSYS_NFTABLES,
		},
	}

	return batch, nil
}
