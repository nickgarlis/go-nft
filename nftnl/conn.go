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

func (c *Conn) receive() ([]Msg, error) {
	var replies []netlink.Message
	var firstErr error
	for {
		ready, err := c.isReadReady()
		if err != nil {
			return nil, err
		}
		if !ready {
			break
		}

		res, err := c.nlconn.Receive()
		if err != nil && firstErr == nil {
			firstErr = err
		}

		for _, m := range res {
			// Filter out non-nftables messages.
			// In practice, this would only be netlink.Error messages.
			// Those are handled by the netlink library itself and should be reported
			// as errors by nlconn.Receive().
			subsystem := m.Header.Type >> 8
			if subsystem != unix.NFNL_SUBSYS_NFTABLES {
				continue
			}

			replies = append(replies, m)
		}
	}

	if firstErr != nil {
		return nil, firstErr
	}

	return c.unmarshalNetlinkMessages(replies)
}

func (c *Conn) Send(msg Msg) ([]Msg, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	_, err := c.sendMessage(msg)
	if err != nil {
		return nil, err
	}

	return c.receive()
}

func (c *Conn) sendMessages(msgs []Msg) ([]Msg, error) {
	nlMsgs, err := c.marshalNetlinkMessages(msgs)
	if err != nil {
		return nil, err
	}

	res, err := c.nlconn.SendMessages(nlMsgs)
	if err != nil {
		return nil, err
	}

	return c.unmarshalNetlinkMessages(res)
}

func (c *Conn) sendMessage(msg Msg) (Msg, error) {
	nlMsg, err := msg.marshal()
	if err != nil {
		return Msg{}, err
	}

	res, err := c.nlconn.Send(nlMsg)
	if err != nil {
		return Msg{}, err
	}

	msgRes := Msg{}
	if err := msgRes.unmarshal(res); err != nil {
		return Msg{}, err
	}

	return msgRes, nil
}

func (c *Conn) marshalNetlinkMessages(msgs []Msg) ([]netlink.Message, error) {
	nlMsgs := make([]netlink.Message, len(msgs))

	for i, msg := range msgs {
		nlMsg, err := msg.marshal()
		if err != nil {
			return nil, err
		}
		nlMsgs[i] = nlMsg
	}

	return nlMsgs, nil
}

func (c *Conn) unmarshalNetlinkMessages(msgs []netlink.Message) ([]Msg, error) {
	result := make([]Msg, len(msgs))

	for i, m := range msgs {
		msg := Msg{}
		if err := msg.unmarshal(m); err != nil {
			return nil, err
		}
		result[i] = msg
	}

	return result, nil
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

	_, err = c.sendMessages(batchMsgs)
	if err != nil {
		return err
	}

	_, err = c.receive()

	return err
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
