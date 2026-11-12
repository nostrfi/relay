package event

// SupportedFilterTags are the tag names the operator event browser can
// filter by (nostrfi/relay#45), with the NIP that defines each.
//
// The list does two jobs. It is what the operator events API accepts as a
// tag filter name, and it is what the tags index stores beyond NIP-01's
// single-letter tags: an allowlisted multi-letter tag (alt, client, ...)
// and a value-less tag (NIP-70's ["-"]) get an index row, so filtering by
// them stays indexed like every other dimension.
//
// Adding a multi-letter name here only indexes events saved from then on.
// Events already stored need a backfill migration for the new name, as
// migration 5 did for this list (infrastructure/duckdb/migrations.go).
//
// The dashboard mirrors this list in frontend/shared/utils/event-query.ts.
var SupportedFilterTags = []string{
	"a",      // NIP-01: references an addressable or replaceable event
	"alt",    // NIP-31: human-readable summary for custom event kinds
	"d",      // NIP-01: identifier for addressable events
	"e",      // NIP-01: references another event
	"g",      // NIP-52: geohash
	"h",      // NIP-29: relay-based group
	"i",      // NIP-39, NIP-35, NIP-73: external identities and content ids
	"p",      // NIP-01: references a pubkey
	"q",      // NIP-18: quote repost
	"rank",   // NIP-85: trusted assertion ranking score
	"r",      // NIP-24, NIP-65: URL or relay address
	"t",      // NIP-24: hashtag
	"-",      // NIP-70: protected event
	"client", // NIP-89: publishing client
	"emoji",  // NIP-30: custom emoji
	"imeta",  // NIP-92: media metadata
	"proxy",  // NIP-48: source on another protocol
	"zap",    // NIP-57: zap recipients
}

var supportedFilterTagSet = func() map[string]struct{} {
	set := make(map[string]struct{}, len(SupportedFilterTags))
	for _, name := range SupportedFilterTags {
		set[name] = struct{}{}
	}
	return set
}()

// IsSupportedFilterTag reports whether name is one of SupportedFilterTags.
func IsSupportedFilterTag(name string) bool {
	_, ok := supportedFilterTagSet[name]
	return ok
}

// IsSingleLetterTag reports whether name is a NIP-01 indexable tag name: a
// single ASCII letter. These are the only tag names a public REQ filter can
// match against stored events.
func IsSingleLetterTag(name string) bool {
	return len(name) == 1 && ((name[0] >= 'a' && name[0] <= 'z') || (name[0] >= 'A' && name[0] <= 'Z'))
}

// IndexedTag returns the row the tags index stores for tag, and whether it
// stores one at all.
//
// Every single-letter tag with a value is indexed, as NIP-01 filtering
// needs. Beyond that, an allowlisted tag is indexed too: by its first value,
// or, when it has none, with hasValue false, so a presence filter can find
// it. The repository stores that case as a NULL value rather than "", so a
// public REQ asking for #e [""] matches exactly what it matched before.
func IndexedTag(tag []string) (name, value string, hasValue, ok bool) {
	if len(tag) == 0 {
		return "", "", false, false
	}
	name = tag[0]
	if len(tag) >= 2 {
		if IsSingleLetterTag(name) || IsSupportedFilterTag(name) {
			return name, tag[1], true, true
		}
		return "", "", false, false
	}
	if IsSupportedFilterTag(name) {
		return name, "", false, true
	}
	return "", "", false, false
}
