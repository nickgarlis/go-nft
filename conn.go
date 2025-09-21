package nft

import "github.com/nickgarlis/go-nft/nftnl"

type Conn struct {
	nftnlConn *nftnl.Conn
}

func Open(config *Config) (*Conn, error) {
	nlConfig := &nftnl.Config{}
	if config != nil {
		nlConfig.NetNS = config.NetNS
	}
	nlConn, err := nftnl.Open(nlConfig)
	if err != nil {
		return nil, err
	}
	return &Conn{nftnlConn: nlConn}, nil
}

func (c *Conn) Close() error {
	return c.nftnlConn.Close()
}

func (c *Conn) SendBatch(b *Batch) error {
	return c.nftnlConn.SendBatch(b.nftnlBatch)
}
