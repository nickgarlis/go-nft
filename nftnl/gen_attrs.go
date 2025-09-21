package nftnl

import "golang.org/x/sys/unix"

type GenAttrs struct {
	ID       uint32
	ProcPID  uint32
	ProcName string
}

func (g *GenAttrs) marshal() ([]byte, error) {
	ae := NewAttributeEncoder()
	ae.Uint32(unix.NFTA_GEN_ID, g.ID)
	if g.ProcPID != 0 {
		ae.Uint32(unix.NFTA_GEN_PROC_PID, g.ProcPID)
	}
	if g.ProcName != "" {
		ae.String(unix.NFTA_GEN_PROC_NAME, g.ProcName)
	}
	return ae.Encode()
}

func (g *GenAttrs) unmarshal(b []byte) error {
	ad, err := NewAttributeDecoder(b)
	if err != nil {
		return err
	}
	for ad.Next() {
		switch ad.Type() {
		case unix.NFTA_GEN_ID:
			g.ID = ad.Uint32()
		case unix.NFTA_GEN_PROC_PID:
			g.ProcPID = ad.Uint32()
		case unix.NFTA_GEN_PROC_NAME:
			g.ProcName = ad.String()
		}
	}
	return nil
}
