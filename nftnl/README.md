
# nftnl

This package provices a low-level API for interacting with `nftables` via
netlink messages in pure Go. It can be used directly, or as a building block for
higher-level libraries.

> **Note:** This library is under development. The API might change as I tinker with the design. 🚧

## Example Usage

```go
package main

import (
	"github.com/mdlayher/netlink"
	"github.com/nickgarlis/go-nft/nftnl"
)

func main() {
	conn, err := nftnl.Open(&nftnl.Config{})
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	batch := nftnl.NewBatch()

	batch.Add(nftnl.Msg{
		Header: nftnl.Header{
			SubsysID: unix.NFNL_SUBSYS_NFTABLES,
			MsgType:  unix.NFT_MSG_NEWTABLE,
			Flags:    netlink.Request | netlink.Acknowledge | netlink.Create,
		},
		NfGenMsg: nftnl.NfGenMsg{
			Family: unix.NFPROTO_IPV4,
		},
		Attrs: &nftnl.TableAttrs{
			Name: "test-table",
		},
	})
	if err := conn.SendBatch(batch); err != nil {
		panic(err)
	}

	msgs, err := conn.Send(nftnl.Msg{
		Header: nftnl.Header{
			SubsysID: unix.NFNL_SUBSYS_NFTABLES,
			MsgType:  unix.NFT_MSG_GETTABLE,
			Flags:    netlink.Request | netlink.Dump,
		},
		NfGenMsg: nftnl.NfGenMsg{
			Family: unix.NFPROTO_IPV4,
		},
	})

	table, _ := msgs[0].Attrs.(*nftnl.TableAttrs)
	fmt.Printf("Created table: %s\n", table.Name)
}
```

## License
This project is licensed under the Apache-2.0 License.
See the [LICENSE](https://github.com/nickgarlis/go-nft/blob/main/LICENSE)
file for details.