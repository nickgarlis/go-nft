package nft

import (
	"github.com/nickgarlis/go-nft/unixext"
	"golang.org/x/sys/unix"
)

type Config struct {
	// NetNS is the network namespace to operate in. If 0, the current
	// network namespace is used.
	NetNS int
}

type CtState uint32

var (
	CtStateInvalid     CtState = unixext.NF_CT_STATE_INVALID_BIT
	CtStateEstablished CtState = CtState(unixext.NfCtStateBit(unixext.IP_CT_ESTABLISHED))
	CtStateRelated     CtState = CtState(unixext.NfCtStateBit(unixext.IP_CT_RELATED))
	CtStateNew         CtState = CtState(unixext.NfCtStateBit(unixext.IP_CT_NEW))
	CtStateUntracked   CtState = unixext.NF_CT_STATE_UNTRACKED_BIT
)

type Family uint8

const (
	FamilyUnspec Family = unix.NFPROTO_UNSPEC
	FamilyIPv4   Family = unix.NFPROTO_IPV4
	FamilyIPv6   Family = unix.NFPROTO_IPV6
	FamilyInet   Family = unix.NFPROTO_INET
	FamilyARP    Family = unix.NFPROTO_ARP
	FamilyNetdev Family = unix.NFPROTO_NETDEV
	FamilyBridge Family = unix.NFPROTO_BRIDGE
)

type TableFlags uint32

const (
	TableFlagDormant TableFlags = unix.NFT_TABLE_F_DORMANT
	TableFlagOwner   TableFlags = unixext.NFT_TABLE_F_OWNER
	TableFlagPersist TableFlags = unixext.NFT_TABLE_F_PERSIST
)

type Hook uint8

const (
	HookPrerouting  Hook = unix.NF_INET_PRE_ROUTING
	HookInput       Hook = unix.NF_INET_LOCAL_IN
	HookForward     Hook = unix.NF_INET_FORWARD
	HookOutput      Hook = unix.NF_INET_LOCAL_OUT
	HookPostrouting Hook = unix.NF_INET_POST_ROUTING
	HookNumhooks    Hook = unix.NF_INET_NUMHOOKS
	HookIngress     Hook = unix.NF_INET_NUMHOOKS
)

type ChainType uint8

const (
	ChainTypeFilter ChainType = 0x1
	ChainTypeRoute  ChainType = 0x2
	ChainTypeNAT    ChainType = 0x3
)

type ChainPolicy uint8

const (
	ChainPolicyAccept   ChainPolicy = 0x1
	ChainPolicyDrop     ChainPolicy = 0x2
	ChainPolicyContinue ChainPolicy = 0x3
)

type VerdictCode int32

const (
	VerdictCodeContinue VerdictCode = unix.NFT_CONTINUE
	VerdictCodeBreak    VerdictCode = unix.NFT_BREAK
	VerdictCodeJump     VerdictCode = unix.NFT_JUMP
	VerdictCodeGoto     VerdictCode = unix.NFT_GOTO
	VerdictCodeReturn   VerdictCode = unix.NFT_RETURN
	VerdictCodeDrop     VerdictCode = unixext.NF_DROP
	VerdictCodeAccept   VerdictCode = unixext.NF_ACCEPT
	VerdictCodeQueue    VerdictCode = unixext.NF_QUEUE
	VerdictCodeRepeat   VerdictCode = unixext.NF_REPEAT
)
