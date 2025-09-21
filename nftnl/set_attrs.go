package nftnl

import (
	"github.com/nickgarlis/go-nft/unixext"
	"golang.org/x/sys/unix"
)

// https://github.com/torvalds/linux/blob/8b789f2b7602a818e7c7488c74414fae21392b63/include/uapi/linux/netfilter/nf_tables.h#L400
type SetAttrs struct {
	Table       string
	Name        string
	Flags       uint32
	KeyType     uint32
	KeyLen      uint32
	DataType    uint32
	DataLen     uint32
	Policy      uint32
	Desc        string
	ID          uint32
	Timeout     uint64
	GCInterval  uint64
	UserData    []byte
	ObjType     uint32
	Handle      uint64
	Expr        ExprDataAttrs
	Expressions []ExprDataAttrs
	Type        string
}

func (a *SetAttrs) marshal() ([]byte, error) {
	ae := NewAttributeEncoder()

	ae.String(unix.NFTA_SET_TABLE, a.Table)
	ae.String(unix.NFTA_SET_NAME, a.Name)
	if a.Flags != 0 {
		ae.Uint32(unix.NFTA_SET_FLAGS, a.Flags)
	}
	if a.ID != 0 {
		ae.Uint32(unix.NFTA_SET_ID, a.ID)
	}
	if a.KeyType != 0 {
		ae.Uint32(unix.NFTA_SET_KEY_TYPE, a.KeyType)
	}
	if a.KeyLen != 0 {
		ae.Uint32(unix.NFTA_SET_KEY_LEN, a.KeyLen)
	}
	if a.DataType != 0 {
		ae.Uint32(unix.NFTA_SET_DATA_TYPE, a.DataType)
	}
	if a.DataLen != 0 {
		ae.Uint32(unix.NFTA_SET_DATA_LEN, a.DataLen)
	}
	if a.Policy != 0 {
		ae.Uint32(unix.NFTA_SET_POLICY, a.Policy)
	}
	if a.Desc != "" {
		ae.String(unix.NFTA_SET_DESC, a.Desc)
	}
	if a.Timeout != 0 {
		ae.Uint64(unix.NFTA_SET_TIMEOUT, a.Timeout)
	}
	if a.GCInterval != 0 {
		ae.Uint64(unix.NFTA_SET_GC_INTERVAL, a.GCInterval)
	}
	if len(a.UserData) > 0 {
		ae.Bytes(unix.NFTA_SET_USERDATA, a.UserData)
	}
	if a.ObjType != 0 {
		ae.Uint32(unix.NFTA_SET_OBJ_TYPE, a.ObjType)
	}
	if a.Handle != 0 {
		ae.Uint64(unixext.NFTA_SET_HANDLE, a.Handle)
	}
	// TODO: Rest of attributes

	return ae.Encode()
}
