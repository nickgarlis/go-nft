package nftnl

import (
	"github.com/mdlayher/netlink"
)

type Msg struct {
	Header   Header
	NfGenMsg NfGenMsg
	Attrs    Attrs
}

func (m *Msg) marshal() (netlink.Message, error) {
	msg := netlink.Message{}
	msg.Header = m.Header.marshal()

	nfgenmsg := m.NfGenMsg.marshal()

	if m.Attrs != nil {
		attrs, err := m.Attrs.marshal()
		if err != nil {
			return netlink.Message{}, err
		}
		msg.Data = append(nfgenmsg, attrs...)
	} else {
		msg.Data = nfgenmsg
	}

	return msg, nil
}

func (m *Msg) unmarshal(msg netlink.Message) error {
	m.Header = Header{}
	if err := m.Header.unmarshal(msg.Header); err != nil {
		return err
	}

	if len(msg.Data) >= 4 {
		m.NfGenMsg = NfGenMsg{}
		if err := m.NfGenMsg.unmarshal(msg); err != nil {
			return err
		}
	}

	if len(msg.Data) > 4 {
		attr, err := attrFactory(m.Header.MsgType)
		if err != nil {
			return err
		}

		if attr == nil {
			// No attributes to unmarshal
			return nil
		}

		m.Attrs = attr

		if err := m.Attrs.unmarshal(msg.Data[4:]); err != nil {
			return err
		}
	}

	return nil
}
