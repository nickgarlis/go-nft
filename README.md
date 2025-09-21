# go-nft (WIP)

[![PkgGoDev](https://img.shields.io/badge/-reference-blue?logo=go&logoColor=white&labelColor=505050)](https://pkg.go.dev/github.com/nickgarlis/go-nft)
[![GitHub](https://img.shields.io/github/license/nickgarlis/go-nft)](https://img.shields.io/github/license/nickgarlis/go-nft)
[![Go Report Card](https://goreportcard.com/badge/github.com/nickgarlis/go-nft)](https://goreportcard.com/report/github.com/nickgarlis/go-nft)

Inspired by [github.com/google/nftables](https://github.com/google/nftables),
this is a higher-level package for interacting with `nftables` in pure Go.

This repository also includes a lower-level package, `nftnl`, for working with
netfilter netlink messages directly, giving more control over the details of
the communication with the kernel without abstracting them away.

> **Note:** This library is under development. The API might change as I tinker with the design. 🚧

## Installation

```bash
go get github.com/nickgarlis/go-nft
```

## Example Usage

```go
package main

import (
	"github.com/nickgarlis/go-nft"
)

func main() {
	conn, err := nft.Open(&nft.Config{})
	if err != nil {
		panic(err)
	}
  defer conn.Close()

  batch := nft.NewBatch()

	tableId, err := batch.AddTable(&nft.Table{
    Family: nft.TableFamilyINet,
    Name:   "my-table",
  })
  if err != nil {
    panic(err)
  }

  chainId, err := batch.AddChain(&nft.Chain{
    TableID: tableId,
    Name:    "my-chain",
    Type:    nft.ChainTypeFilter,
    Hook:    nft.ChainHookInput,
    Priority: 0,
    Policy:  nft.ChainPolicyAccept,
  })
  if err != nil {
    panic(err)
  }

  _, err = batch.AddRule(&nft.Rule{
    TableID: tableId,
    ChainID: chainId,
    SrcIPv4: &nft.IPMatch{
      Prefix: netip.MustParsePrefix("10.0.0.0/24"),
    },
    Action: &nft.RuleAction{
      Verdict: nft.VerdictCodeAccept,
    }
  })
	if err != nil {
		panic(err)
	}

  err := conn.SendBatch(batch)
  if err != nil {
    panic(err)
  }
}
```

## License
This project is licensed under the Apache-2.0 License.
See the [LICENSE](https://github.com/nickgarlis/go-nft/blob/main/LICENSE) file for details.