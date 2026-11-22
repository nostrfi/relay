package ws

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Control frames must stay byte-identical to the json.Marshal output the
// relay sent before they were pooled, including HTML and control-character
// escaping of client-supplied subscription ids and of reasons.
func TestControlFramesMatchJSONMarshal(t *testing.T) {
	awkward := `<sub>&"quoted"\` + "  \x00\t\xff" + `é🙂`
	frames := []struct {
		name  string
		frame []any
	}{
		{"ok accepted", []any{"OK", strings.Repeat("a", 64), true, ""}},
		{"ok rejected", []any{"OK", strings.Repeat("b", 64), false, "blocked: <script>&nope</script>"}},
		{"notice", []any{"NOTICE", "rate-limited: " + awkward}},
		{"auth", []any{"AUTH", newChallenge()}},
		{"eose", []any{"EOSE", awkward}},
		{"closed", []any{"CLOSED", awkward, "error: " + awkward}},
		{"neg-err", []any{"NEG-ERR", awkward, "blocked: too many"}},
		{"neg-msg", []any{"NEG-MSG", awkward, strings.Repeat("0f", 4096)}},
		{"oversized", []any{"NOTICE", strings.Repeat("x", 2*maxPooledFrame)}},
	}
	e := controlPool.Get().(*controlEncoder)
	defer controlPool.Put(e)
	for _, tt := range frames {
		t.Run(tt.name, func(t *testing.T) {
			want, err := json.Marshal(tt.frame)
			require.NoError(t, err)
			got, err := e.encode(tt.frame)
			require.NoError(t, err)
			assert.Equal(t, string(want), string(got))
		})
	}
}

// BenchmarkControlFrame compares the old per-frame json.Marshal with the
// pooled encoder; commit the pooled path only if it allocates less.
func BenchmarkControlFrame(b *testing.B) {
	id := strings.Repeat("a", 64)
	b.Run("marshal", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			msg, _ := json.Marshal([]any{"OK", id, false, "blocked: pubkey is banned"})
			_ = msg
		}
	})
	b.Run("pooled", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			e := controlPool.Get().(*controlEncoder)
			msg, _ := e.encode([]any{"OK", id, false, "blocked: pubkey is banned"})
			_ = msg
			controlPool.Put(e)
		}
	})
}
