package ws

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewChallengeIsSixteenRandomBytes(t *testing.T) {
	const n = 64
	seen := make(map[string]struct{}, n)
	byteValues := make(map[byte]struct{})
	for range n {
		c := newChallenge()
		require.Len(t, c, 2*challengeBytes)
		raw, err := hex.DecodeString(c)
		require.NoError(t, err, "challenge must be lowercase hex")
		assert.Equal(t, hex.EncodeToString(raw), c)
		seen[c] = struct{}{}
		for _, b := range raw {
			byteValues[b] = struct{}{}
		}
	}
	assert.Len(t, seen, n, "challenges must not repeat")
	// A challenge built by hex-encoding a hex string decodes only to the
	// 16 ASCII bytes '0'-'9' and 'a'-'f', so it carries half the entropy
	// its length suggests. 1024 genuinely random bytes cover far more than
	// 16 of the 256 possible values.
	assert.Greater(t, len(byteValues), 16, "challenge bytes are restricted to hex ASCII")
}
