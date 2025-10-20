package nftnl

import (
	"fmt"
	"sync"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

type Config struct {
	// NetNS is the network namespace to operate in. If 0, the current
	// network namespace is used.
	NetNS int
}

type Conn struct {
	// netlink socket using NETLINK_NETFILTER protocol.
	nlconn *netlink.Conn
	mu     sync.Mutex
}

func Open(config *Config) (*Conn, error) {
	if config == nil {
		config = &Config{}
	}
	nlconn, err := netlink.Dial(unix.NETLINK_NETFILTER, &netlink.Config{
		NetNS: config.NetNS,
	})
	if err != nil {
		return nil, err
	}
	return &Conn{
		nlconn: nlconn,
	}, nil
}

func (c *Conn) send(msg Msg) ([]netlink.Message, error) {
	nlMsg, err := msg.marshal()
	if err != nil {
		return nil, err
	}

	req, err := c.nlconn.Send(nlMsg)
	if err != nil {
		return nil, err
	}

	res, err := c.nlconn.Receive()
	if err != nil {
		return nil, err
	}

	if len(res) == 0 {
		return res, nil
	}

	if res[0].Header.Sequence != req.Header.Sequence {
		return nil, fmt.Errorf("send: expected response with sequence %d, got %d", req.Header.Sequence, res[0].Header.Sequence)
	}

	if nlMsg.Header.Flags&netlink.Acknowledge == 0 {
		return res, nil
	}

	if nlMsg.Header.Flags&netlink.Dump == netlink.Dump {
		return res, nil
	}

	// TODO: Validate ack message and sequence number ?
	return c.nlconn.Receive()
}

func (c *Conn) Send(msg Msg) ([]Msg, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	resMsg, err := c.send(msg)
	if err != nil {
		return nil, err
	}

	results := make([]Msg, len(resMsg))

	for i, m := range resMsg {
		msg := Msg{}
		if err := msg.unmarshal(m); err != nil {
			return nil, err
		}

		results[i] = msg
	}

	return results, nil
}

func (c *Conn) sendBatch(msgs []Msg) ([]netlink.Message, error) {
	nlMsgs := make([]netlink.Message, len(msgs))

	for i, msg := range msgs {
		nlMsg, err := msg.marshal()
		if err != nil {
			return nil, err
		}
		nlMsgs[i] = nlMsg
	}

	return c.nlconn.SendMessages(nlMsgs)
}

func (c *Conn) SendBatch(batch *Batch) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	batchMsgs, err := batch.Marshal()
	if err != nil {
		return err
	}

	// TODO: Maybe allow echo messages in batch ?
	// That would complicate response handling though.
	for _, m := range batchMsgs {
		if m.Header.Flags&netlink.Echo == netlink.Echo {
			return fmt.Errorf("SendBatch: batch cannot contain echo messages")
		}

		if m.Header.Flags&netlink.Dump == netlink.Dump {
			return fmt.Errorf("SendBatch: batch cannot contain dump messages")
		}
	}

	if _, err = c.sendBatch(batchMsgs); err != nil {
		return err
	}

	var firstError error

	for {
		ready, err := c.isReadReady()
		if err != nil {
			return err
		}
		if !ready {
			break
		}
		if _, err = c.nlconn.Receive(); err != nil {
			firstError = err
		}
	}

	if firstError != nil {
		return firstError
	}

	return nil
}

// isReadReady checks if there is data available to read from the netlink
// socket. It uses pselect with a zero timeout. If an error occurs during the
// pselect call, it is returned.
func (c *Conn) isReadReady() (bool, error) {
	rawConn, err := c.nlconn.SyscallConn()
	if err != nil {
		return false, fmt.Errorf("get raw conn: %w", err)
	}

	var readErr error
	var n int
	err = rawConn.Read(func(fd uintptr) bool {
		var readfds unix.FdSet
		readfds.Zero()
		readfds.Set(int(fd))
		n, readErr = unix.Pselect(
			int(fd)+1, &readfds, nil, nil, &unix.Timespec{}, nil,
		)
		// Return true to stop retrying immediately (no polling)
		return true
	})

	if err != nil {
		return false, err
	}

	return n > 0, readErr
}

func (c *Conn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.nlconn.Close()
}
