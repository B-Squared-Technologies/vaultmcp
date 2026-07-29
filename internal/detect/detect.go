// Package detect finds credentials in arbitrary text using two complementary
// methods: known-format regexes (high precision) and a Shannon-entropy scan
// (high recall for unknown/custom secrets). Ported from the Python original
// with an added path-like allowlist heuristic to cut entropy false positives.
package detect

import (
	"math"
	"regexp"
	"strings"
)

const (
	entropyThreshold = 3.5
	minTokenLen      = 20
	maxTokenLen      = 2048
)

// Match is a detected credential and where it was found.
type Match struct {
	Value string
	Type  string // hint used to name the alias, e.g. "aws_access_key"
}

type pattern struct {
	re   *regexp.Regexp
	kind string
}

// Go's regexp (RE2) has no backreferences but covers everything needed here.
var known = []pattern{
	{regexp.MustCompile(`AKIA[0-9A-Z]{16}`), "aws_access_key"},
	{regexp.MustCompile(`(?i)aws.{0,20}secret.{0,20}[=:]\s*\S{20,}`), "aws_secret"},
	{regexp.MustCompile(`ghp_[a-zA-Z0-9]{20,}`), "github_token"},
	{regexp.MustCompile(`ghs_[a-zA-Z0-9]{20,}`), "github_token"},
	{regexp.MustCompile(`sk-ant-[a-zA-Z0-9\-_]{32,}`), "anthropic_key"},
	{regexp.MustCompile(`sk-[a-zA-Z0-9]{32,}`), "openai_key"},
	{regexp.MustCompile(`xoxb-[0-9]+-[0-9]+-[a-zA-Z0-9]+`), "slack_bot_token"},
	{regexp.MustCompile(`xoxp-[0-9]+-[0-9]+-[a-zA-Z0-9]+`), "slack_user_token"},
	{regexp.MustCompile(`stripe[_-]?(?:sk|pk)[_-](?:live|test)_[a-zA-Z0-9]{24,}`), "stripe_key"},
	{regexp.MustCompile(`-----BEGIN (?:RSA |EC )?PRIVATE KEY-----`), "private_key"},
	{regexp.MustCompile(`(?i)postgres(?:ql)?://[^:]+:[^@]{8,}@`), "db_connection_string"},
	{regexp.MustCompile(`(?i)mysql://[^:]+:[^@]{8,}@`), "db_connection_string"},
	{regexp.MustCompile(`(?i)mongodb(?:\+srv)?://[^:]+:[^@]{8,}@`), "db_connection_string"},
	{regexp.MustCompile(`(?i)redis://:?[^@]{8,}@`), "redis_url"},
	{regexp.MustCompile(`ey[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}`), "jwt_token"},
}

var allowlist = []*regexp.Regexp{
	regexp.MustCompile(`^https?://`),
	regexp.MustCompile(`^\$\{`),
	regexp.MustCompile(`^\$\(`),
	regexp.MustCompile(`^\[vault:`),
	regexp.MustCompile(`^vault:`), // tokenizer strips the leading '[' of [vault:X]
	regexp.MustCompile(`^<[a-zA-Z]`),
	regexp.MustCompile(`localhost`),
	regexp.MustCompile(`(?i)^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`), // UUID
	regexp.MustCompile(`^[A-Z][A-Z0-9]*(_[A-Z0-9]+)+$`),                                      // SCREAMING_SNAKE env-var name, e.g. ${MY_VAR}
	// Structural non-secrets that repeatedly false-positived in real sessions
	// (2026-07: task UUIDs in prose, ISO timestamps in JSON, date-prefixed doc
	// filenames, file:line code references — all got vaulted and corrupted
	// written artifacts). These are shape allowlists for machine-formatted
	// data, not key material; known-pattern secret regexes still run first.
	regexp.MustCompile(`^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}`),         // ISO 8601 timestamp (any suffix)
	regexp.MustCompile(`(?i)^\d{4}-\d{2}-\d{2}[-_][a-z0-9][a-z0-9._-]*$`), // date-prefixed slug/filename
	regexp.MustCompile(`(?i)^[\w./-]+\.[a-z]{1,5}:\d+\)?$`),               // file.ext:line code reference
	regexp.MustCompile(`(?i)^[a-z0-9]+([._-][a-z0-9]+)+\.[a-z]{1,5}$`),    // dotted/hyphenated filename, e.g. spider.config.template
	// 2026-07-28: digit-bearing code identifiers, Go import paths, and module
	// pseudo-versions — vaulted out of tool results (source reads, go build
	// output) and would corrupt an Edit carrying them. Key material never ends
	// in a pure-letter dotted segment, is never host.tld/path shaped, and is
	// never a semver pseudo-version.
	regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*\.[A-Za-z_]+$`), // dotted code identifier, e.g. pkg.SymbolName
	regexp.MustCompile(`^[a-z0-9-]+(\.[a-z0-9-]+)+(/[A-Za-z0-9._~-]+)+$`),                 // host.tld/path — Go import path, URL path
	regexp.MustCompile(`^v\d+\.\d+\.\d+(-\d{14}-[a-f0-9]{12})?$`),                         // semver / Go module pseudo-version
	regexp.MustCompile(`^[a-z0-9]+([._-][a-z0-9]+)*[._-](19|20)\d{6}$`),                   // date-suffixed filename/slug, e.g. [vault:HIGH_ENTROPY_SECRET]
}

// entropyTokens matches whitespace/punctuation-delimited candidate tokens. The
// upper length bound is enforced in Find (RE2 caps bounded repeats at 1000).
// Backslash and backtick are delimiters too: PreToolUse scans the raw JSON of
// tool_input, where a newline is the literal two-byte sequence \n — without
// the backslash split, a date followed by a bold heading on the next line
// scans as one high-entropy token and a Write's file content gets corrupted
// on disk. Markdown code spans similarly smuggle backticks into tokens and
// defeat the path allowlist. Real key material virtually never contains
// either character.
var entropyTokens = regexp.MustCompile("[^\\s,'\";\\[\\]{}()\\n\\\\`]{20,}")

func shannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	freq := make(map[rune]int, len(s))
	for _, c := range s {
		freq[c]++
	}
	n := float64(len([]rune(s)))
	var h float64
	for _, f := range freq {
		p := float64(f) / n
		h -= p * math.Log2(p)
	}
	return h
}

// containsSeen reports whether tok strictly contains an already-detected
// secret as a substring (so the inner secret, not the wrapping token, is what
// gets vaulted).
func containsSeen(tok string, seen map[string]bool) bool {
	for s := range seen {
		if s != tok && strings.Contains(tok, s) {
			return true
		}
	}
	return false
}

func digitCount(s string) int {
	n := 0
	for _, c := range s {
		if c >= '0' && c <= '9' {
			n++
		}
	}
	return n
}

func isAllowlisted(tok string) bool {
	for _, re := range allowlist {
		if re.MatchString(tok) {
			return true
		}
	}
	return false
}

// fileExt matches a short trailing extension (".md", ".ts", ".config").
var fileExt = regexp.MustCompile(`(?i)\.[a-z0-9]{1,6}$`)

// looksLikePath rejects filesystem paths, the dominant entropy false
// positive. Long or deeply-nested tokens are paths, and so is ANY
// slash-separated token ending in a file extension — shallow repo-relative
// paths (lib/data/reviews-2026.ts) burned us repeatedly. A real
// secret is rarely slash-separated with a tidy extension.
func looksLikePath(tok string) bool {
	seps := strings.Count(tok, "/") + strings.Count(tok, `\`)
	if seps == 0 {
		return false
	}
	if fileExt.MatchString(tok) {
		return true
	}
	return len(tok) > 80 || seps > 3
}

// Find returns all detected credentials in text, de-duplicated by value, with
// known-pattern hits taking precedence over generic entropy hits.
func Find(text string) []Match {
	var out []Match
	seen := make(map[string]bool)

	for _, p := range known {
		for _, val := range p.re.FindAllString(text, -1) {
			if !seen[val] && !isAllowlisted(val) {
				out = append(out, Match{Value: val, Type: p.kind})
				seen[val] = true
			}
		}
	}

	for _, val := range entropyTokens.FindAllString(text, -1) {
		// Sentence punctuation rides along in prose ("…task 44cb0f45-…-ef.")
		// and defeats the anchored allowlist shapes — strip it before any
		// check so a UUID followed by a period is still recognized as a UUID.
		val = strings.TrimRight(val, ".,:;!?")
		if seen[val] || isAllowlisted(val) || looksLikePath(val) {
			continue
		}
		if len(val) < minTokenLen || len(val) > maxTokenLen {
			continue
		}
		// Code identifiers (camelCase, PascalCase, dotted member access) routinely
		// clear the entropy bar but are not secrets — they corrupted agent edits
		// when vaulted. Random key material virtually always carries digits, so
		// require a couple before the entropy test may fire.
		if digitCount(val) < 2 {
			continue
		}
		// Skip a token that merely *contains* a secret we already matched (e.g.
		// the whole line "AWS_KEY=AKIA…" wrapping a known AKIA key). Vaulting the
		// superstring too would pollute the vault with redundant aliases.
		if containsSeen(val, seen) {
			continue
		}
		if shannonEntropy(val) >= entropyThreshold {
			out = append(out, Match{Value: val, Type: "high_entropy_secret"})
			seen[val] = true
		}
	}

	return out
}
