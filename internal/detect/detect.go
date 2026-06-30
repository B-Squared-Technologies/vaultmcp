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
}

// entropyTokens matches whitespace/punctuation-delimited candidate tokens. The
// upper length bound is enforced in Find (RE2 caps bounded repeats at 1000).
var entropyTokens = regexp.MustCompile(`[^\s,'";\[\]{}()\n]{20,}`)

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

func isAllowlisted(tok string) bool {
	for _, re := range allowlist {
		if re.MatchString(tok) {
			return true
		}
	}
	return false
}

// looksLikePath rejects long filesystem paths, the dominant entropy false
// positive (e.g. /tmp/some/deeply/nested/build/artifact path). A real secret
// is rarely both path-shaped and very long.
func looksLikePath(tok string) bool {
	seps := strings.Count(tok, "/") + strings.Count(tok, `\`)
	if seps == 0 {
		return false
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
		if seen[val] || isAllowlisted(val) || looksLikePath(val) {
			continue
		}
		if len(val) < minTokenLen || len(val) > maxTokenLen {
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
