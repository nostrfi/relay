package ws

import (
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/nbd-wtf/go-nostr"
)

// nip50ExtensionKeys are the extension keys NIP-50 names. A token of the
// form "<key>:<value>" using one of these is an extension request, and this
// relay supports none of them, so the NIP says to ignore it.
//
// Ignoring means dropping it from the search text, not searching for it:
// a client asking for `orange domain:example.com` wants notes about
// oranges, and looking for the literal string "domain:example.com" in
// their content would return nothing at all.
//
// Deliberately a fixed list rather than "anything containing a colon".
// Colons are ordinary text — a URL, a time of day, a ratio — and a relay
// that silently deleted "https://example.com" from a query would be
// answering a question nobody asked.
var nip50ExtensionKeys = map[string]bool{
	"include":   true,
	"domain":    true,
	"language":  true,
	"sentiment": true,
	"nsfw":      true,
}

// parseSearchTerm turns a NIP-50 `search` value into the text to match
// against event content: extension tokens removed, surrounding whitespace
// collapsed to single spaces.
//
// An empty result means the query carried no searchable text — either it
// was blank, or it consisted entirely of extensions this relay ignores.
// The caller distinguishes that from "no search requested" by checking the
// original field, since the two need different answers.
func parseSearchTerm(raw string) string {
	fields := strings.Fields(raw)
	kept := make([]string, 0, len(fields))
	for _, field := range fields {
		if key, _, found := strings.Cut(field, ":"); found && nip50ExtensionKeys[strings.ToLower(key)] {
			continue
		}
		kept = append(kept, field)
	}
	return strings.Join(kept, " ")
}

// defaultSearchLimit bounds a search REQ that asks for no limit.
//
// Every other REQ can be answered from an index; a search cannot, so an
// unbounded one reads the table. This is not a new number: it is the
// relay's own advertised max_limit, so a search behaves like any other REQ
// clamped to that ceiling rather than obeying a second, stricter rule
// invented here. fallbackSearchLimit covers a relay advertising no
// max_limit of its own, matching what config.yaml ships.
const fallbackSearchLimit = 500

// prepareSearchFilters normalizes every NIP-50 search filter in place and
// reports whether the REQ may proceed.
//
// Normalizing here rather than at each use means the stored query and the
// live-subscription matcher both see the same text, and neither has to
// remember to strip extensions. It returns a CLOSED reason rather than
// silently dropping the term: a search this relay will not run should say
// so, since a client cannot tell an empty result from an ignored field.
func prepareSearchFilters(filters []nostr.Filter, limitation *RelayLimitation) (string, bool) {
	for i := range filters {
		if filters[i].Search == "" {
			continue
		}

		term := parseSearchTerm(filters[i].Search)
		if term == "" {
			return fmt.Sprintf("%s: search query contained no searchable text; %s", prefixInvalid, extensionsAreIgnoredNote), false
		}
		if utf8.RuneCountInString(term) < minContentSearchRunes {
			return fmt.Sprintf("%s: search query must be at least %d characters", prefixInvalid, minContentSearchRunes), false
		}
		filters[i].Search = term

		// LimitZero distinguishes an explicit "limit":0 — a client asking
		// for no stored events at all — from an omitted limit. Only the
		// latter gets a default.
		if filters[i].Limit == 0 && !filters[i].LimitZero {
			filters[i].Limit = fallbackSearchLimit
			if limitation != nil && limitation.MaxLimit > 0 {
				filters[i].Limit = limitation.MaxLimit
			}
		}
	}
	return "", true
}

// extensionsAreIgnoredNote explains the one refusal a client is most likely
// to find surprising: a query made entirely of NIP-50 extensions, which
// this relay supports none of, leaves nothing to search for.
const extensionsAreIgnoredNote = "this relay supports no NIP-50 extensions and ignores them"
