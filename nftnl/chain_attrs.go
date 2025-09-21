package nftnl

import (
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// https://github.com/torvalds/linux/blob/f83a4f2a4d8c485922fba3018a64fc8f4cfd315f/include/uapi/linux/netfilter/nf_tables.h#L168
type HookAttrs struct {
	Number uint32
	// Values https://github.com/torvalds/linux/blob/f83a4f2a4d8c485922fba3018a64fc8f4cfd315f/include/uapi/linux/netfilter_ipv4.h#L30
	Priority int32
	Dev      string
	// Missing devs
}

func (a *HookAttrs) marshal() ([]byte, error) {
	ae := NewAttributeEncoder()
	ae.Uint32(unix.NFTA_HOOK_HOOKNUM, a.Number)
	ae.Uint32(unix.NFTA_HOOK_PRIORITY, uint32(a.Priority))
	if a.Dev != "" {
		ae.String(unix.NFTA_HOOK_DEV, a.Dev)
	}

	return ae.Encode()
}

func (a *HookAttrs) unmarshal(data []byte) error {
	ad, err := netlink.NewAttributeDecoder(data)
	if err != nil {
		return err
	}

	for ad.Next() {
		switch ad.Type() {
		case unix.NFTA_HOOK_HOOKNUM:
			a.Number = ad.Uint32()
		case unix.NFTA_HOOK_PRIORITY:
			a.Priority = int32(ad.Uint32())
		case unix.NFTA_HOOK_DEV:
			a.Dev = ad.String()
		}
	}

	return nil
}

// https://github.com/torvalds/linux/blob/f83a4f2a4d8c485922fba3018a64fc8f4cfd315f/include/uapi/linux/netfilter/nf_tables.h#L240
type ChainAttrs struct {
	Table    string
	Handle   uint64
	Name     string
	Hook     *HookAttrs
	Policy   uint32
	Use      uint32
	Type     string
	Counters *CounterAttrs
	Flags    uint32
	ID       uint32
	UserData []byte
}

func (a *ChainAttrs) marshal() ([]byte, error) {
	ae := NewAttributeEncoder()
	ae.String(unix.NFTA_TABLE_NAME, a.Table)
	ae.String(unix.NFTA_CHAIN_NAME, a.Name)
	if a.Handle > 0 {
		ae.Uint64(unix.NFTA_CHAIN_HANDLE, a.Handle)
	}

	if a.Counters != nil {
		counter, err := a.Counters.marshal()
		if err != nil {
			return nil, err
		}
		ae.Bytes(unix.NLA_F_NESTED|unix.NFTA_CHAIN_COUNTERS, counter)
	}

	if a.Hook != nil {
		hook, err := a.Hook.marshal()
		if err != nil {
			return nil, err
		}
		ae.Bytes(unix.NLA_F_NESTED|unix.NFTA_CHAIN_HOOK, hook)
		ae.Uint32(unix.NFTA_CHAIN_POLICY, a.Policy)
	}

	return ae.Encode()
}

func (a *ChainAttrs) unmarshal(data []byte) error {
	ad, err := netlink.NewAttributeDecoder(data)
	if err != nil {
		return err
	}

	for ad.Next() {
		switch ad.Type() {
		case unix.NFTA_TABLE_NAME:
			a.Table = ad.String()
		case unix.NFTA_CHAIN_NAME:
			a.Name = ad.String()
		case unix.NFTA_CHAIN_HANDLE:
			a.Handle = ad.Uint64()
		case unix.NFTA_CHAIN_POLICY:
			a.Policy = ad.Uint32()
		case unix.NFTA_CHAIN_USE:
			a.Use = ad.Uint32()
		case unix.NFTA_CHAIN_TYPE:
			a.Type = ad.String()
		case unix.NFTA_CHAIN_COUNTERS:
			if err := a.Counters.unmarshal(ad.Bytes()); err != nil {
				return err
			}
		case unix.NFTA_CHAIN_HOOK:
			if err := a.Hook.unmarshal(ad.Bytes()); err != nil {
				return err
			}
		}
	}

	return nil
}
