package nftnl

import (
	"errors"
	"fmt"
	"syscall"

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
	res, err := c.nlconn.Execute(nlMsg)
	if err != nil {
		return nil, err
	}
	return res, err
}

func (c *Conn) Send(msg Msg) ([]Msg, error) {
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
	nlMsgs, err := batch.Marshal()
	if err != nil {
		return err
	}

	_, err = c.sendBatch(nlMsgs)
	if err != nil {
		return err
	}

	// TODO: handle echo messages

	var errs error

	for _, m := range batch.messages {
		if m.Header.Flags&netlink.Acknowledge == 0 {
			continue
		}
		ack, err := c.nlconn.Receive()
		if err != nil {
			// If the error is a kernel error, there will be no more acks to read.
			// Return the kernel error as the main error.
			// Any other errors are collected and returned at the end.
			var errno syscall.Errno
			if errors.As(err, &errno) {
				err = fmt.Errorf("kernel error: %s: %w", m.Header.MsgTypeString(), errno)
				switch errno {
				// If any of these errors are encountered,
				// there will be no more acks to read.
				// TODO: is there a better way to detect this?
				// See: https://github.com/torvalds/linux/blob/36a686c0784fcccdaa4f38b498a9ef0d42ea7cb8/net/netfilter/nfnetlink.c#L371
				case syscall.EPERM, syscall.ENOBUFS, syscall.ENOMEM, syscall.EOPNOTSUPP:
					return err
				}
			}
			errs = errors.Join(errs, err)
		}

		if len(ack) == 0 {
			errors.Join(errs, fmt.Errorf("SendBatch: no ack received"))
		}
	}

	if errs != nil {
		return errs
	}

	return nil
}

func (c *Conn) Close() error {
	return c.nlconn.Close()
}
