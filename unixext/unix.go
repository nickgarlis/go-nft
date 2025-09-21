package unixext

const (
	NFTA_TABLE_HANDLE   = 0x04
	NFTA_TABLE_USERDATA = 0x06
	NFTA_TABLE_OWNER    = 0x07
)

const (
	NFTA_VERDICT_CHAINID = 0x03
)

// https://github.com/torvalds/linux/blob/8b789f2b7602a818e7c7488c74414fae21392b63/include/uapi/linux/netfilter.h#L11
const (
	NF_DROP = iota
	NF_ACCEPT

	// Not relevant for nftables: https://github.com/torvalds/linux/blob/8b789f2b7602a818e7c7488c74414fae21392b63/net/netfilter/nf_tables_api.c#L11773
	NF_STOLEN

	NF_QUEUE

	// Not relevant for nftables: https://github.com/torvalds/linux/blob/8b789f2b7602a818e7c7488c74414fae21392b63/net/netfilter/nf_tables_api.c#L11773
	NF_REPEAT
)

// https://github.com/torvalds/linux/blob/8b789f2b7602a818e7c7488c74414fae21392b63/include/uapi/linux/netfilter.h#L42C1-L50C3
const (
	NF_INET_PRE_ROUTING = iota
	NF_INET_LOCAL_IN
	NF_INET_FORWARD
	NF_INET_LOCAL_OUT
	NF_INET_POST_ROUTING
	NF_INET_NUMHOOKS
	NF_INET_INGRESS = NF_INET_NUMHOOKS
)

// https://github.com/torvalds/linux/blob/8b789f2b7602a818e7c7488c74414fae21392b63/include/uapi/linux/netfilter/nf_conntrack_common.h#L7
const (
	IP_CT_ESTABLISHED = iota
	IP_CT_RELATED
	IP_CT_NEW
	IP_CT_IS_REPLY
	IP_CT_ESTABLISHED_REPLY = IP_CT_ESTABLISHED + IP_CT_IS_REPLY
	IP_CT_RELATED_REPLY     = IP_CT_RELATED + IP_CT_IS_REPLY
	IP_CT_NUMBER
	IP_CT_NEW_REPLY = IP_CT_NUMBER
	IP_CT_UNTRACKED = 7
)

func NfCtStateBit(ctinfo uint32) uint32 {
	return (1 << ((ctinfo)%IP_CT_IS_REPLY + 1))
}

// https://github.com/torvalds/linux/blob/8b789f2b7602a818e7c7488c74414fae21392b63/include/uapi/linux/netfilter/nf_conntrack_common.h#L37
const (
	NF_CT_STATE_INVALID_BIT   = 1 << 0
	NF_CT_STATE_UNTRACKED_BIT = 1 << 6
)

// https://github.com/torvalds/linux/blob/8b789f2b7602a818e7c7488c74414fae21392b63/include/uapi/linux/netfilter/nf_tables.h#L185
const (
	NFT_TABLE_F_OWNER   = 0x2
	NFT_TABLE_F_PERSIST = 0x4
)

// https://github.com/torvalds/linux/blob/f83a4f2a4d8c485922fba3018a64fc8f4cfd315f/include/uapi/linux/netfilter/nf_tables.h#L462
const (
	NFTA_SET_ELEM_KEY_END     = 0x0a
	NFTA_SET_ELEM_EXPRESSIONS = 0x0b
)

// https://github.com/torvalds/linux/blob/8b789f2b7602a818e7c7488c74414fae21392b63/include/uapi/linux/netfilter/nf_tables.h#L400
const (
	NFTA_SET_HANDLE      = 0x10
	NFTA_SET_EXPR        = 0x11
	NFTA_SET_EXPRESSIONS = 0x12
	NFTA_SET_TYPE        = 0x13
	NFTA_SET_COUNT       = 0x14
)
