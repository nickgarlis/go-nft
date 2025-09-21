package unixext

import "testing"

func TestCtStateBit(t *testing.T) {

	tt := []struct {
		ctinfo uint32
		want   uint32
	}{
		{ctinfo: IP_CT_ESTABLISHED, want: 2},
		{ctinfo: IP_CT_RELATED, want: 4},
		{ctinfo: IP_CT_NEW, want: 8},
	}

	for _, tc := range tt {
		if got := NfCtStateBit(tc.ctinfo); got != tc.want {
			t.Errorf("NfCtStateBit(%d) = %d; want %d", tc.ctinfo, got, tc.want)
		}
	}
}
