package event

import "testing"

func TestIsEphemeral(t *testing.T) {
	cases := []struct {
		kind int
		want bool
	}{
		{1, false},
		{19999, false},
		{20000, true},
		{20001, true},
		{24133, true},
		{29999, true},
		{30000, false},
	}
	for _, tc := range cases {
		if got := IsEphemeral(tc.kind); got != tc.want {
			t.Errorf("IsEphemeral(%d) = %v, want %v", tc.kind, got, tc.want)
		}
	}
}
