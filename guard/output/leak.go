// Package output implements output-side guards that validate LLM responses for
// security issues such as system prompt leakage, canary token leakage, and
// policy-violating content.
package output

import (
	"regexp"
	"strings"
)

// leakMatch represents a single system prompt leak detection match.
type leakMatch struct {
	pattern     string
	match       string
	start       int
	end         int
	description string
	severity    float64
}

// leakEntry holds a compiled pattern along with its metadata.
type leakEntry struct {
	re          *regexp.Regexp
	description string
	severity    float64
}

// leakPatterns contains all compiled system prompt leak detection patterns.
// They are initialised once at package init time.
var leakPatterns []leakEntry

func init() {
	raw := []struct {
		pattern     string
		description string
		severity    float64
	}{
		// -- Direct instruction disclosure --
		{
			`(?i)\bmy\s+(system\s+|initial\s+)?instructions\s+(are|say|tell)`,
			"LLM disclosing its instructions via 'my instructions are/say/tell'",
			0.9,
		},
		{
			`(?i)\bI\s+was\s+(told|instructed|programmed)\s+to\b`,
			"LLM revealing directives via 'I was told/instructed/programmed to'",
			0.85,
		},
		{
			`(?i)\bmy\s+(system\s+)?prompt\s+(is|says|contains)\b`,
			"LLM disclosing system prompt via 'my prompt is/says/contains'",
			0.9,
		},
		{
			`(?i)\bhere\s+(are|is)\s+my\s+(system\s+)?(prompt|instructions)\b`,
			"LLM presenting its prompt/instructions via 'here is/are my ...'",
			0.95,
		},
		{
			`(?i)\bthe\s+(system\s+)?(prompt|instructions)\s+(I\s+|that\s+I\s+)?(was\s+given|received)\b`,
			"LLM referencing received prompt/instructions",
			0.9,
		},

		// -- Paraphrased disclosure --
		{
			`(?i)\bI\s+have\s+been\s+(told|instructed|configured|set\s+up)\s+to\b`,
			"LLM revealing configuration via 'I have been told/instructed to'",
			0.8,
		},
		{
			`(?i)\bmy\s+(original|initial|base)\s+(instructions|prompt|programming)\b`,
			"LLM referencing original instructions/programming",
			0.85,
		},
		{
			`(?i)\bI('m|\s+am)\s+(designed|built|programmed|configured)\s+to\b`,
			"LLM revealing design constraints via 'I am designed/programmed to'",
			0.6,
		},
		{
			`(?i)\bmy\s+(guidelines|directives|rules)\s+(are|include|say|state)\b`,
			"LLM disclosing guidelines/directives/rules",
			0.85,
		},
		{
			`(?i)\baccording\s+to\s+my\s+(instructions|prompt|rules|guidelines)\b`,
			"LLM citing its instructions via 'according to my ...'",
			0.8,
		},

		// -- Verbatim output markers --
		{
			`(?i)\bbelow\s+is\s+(my|the)\s+(system\s+)?(prompt|instructions)\b`,
			"LLM presenting prompt verbatim via 'below is my/the prompt'",
			0.95,
		},
		{
			`(?i)\bthe\s+exact\s+(text|wording|content)\s+of\s+my\s+(system\s+)?(prompt|instructions)\b`,
			"LLM disclosing exact prompt wording",
			0.95,
		},
		{
			`(?i)\bI\s+will\s+(now\s+)?(share|reveal|show|display|output)\s+(my|the)\s+(system\s+)?(prompt|instructions)\b`,
			"LLM announcing it will share its prompt/instructions",
			0.95,
		},

		// -- Internal configuration references --
		{
			`(?i)\bmy\s+system\s+message\s+(is|says|reads|contains)\b`,
			"LLM referencing its system message",
			0.9,
		},
		{
			`(?i)\bI\s+was\s+(given|provided)\s+(the\s+following\s+)?(system\s+)?(instructions|prompt|message)\b`,
			"LLM disclosing that it was given a system prompt",
			0.85,
		},
	}

	leakPatterns = make([]leakEntry, 0, len(raw))
	for _, r := range raw {
		leakPatterns = append(leakPatterns, leakEntry{
			re:          regexp.MustCompile(r.pattern),
			description: r.description,
			severity:    r.severity,
		})
	}
}

// checkLeaks scans output for patterns indicating the LLM is leaking its
// system prompt or internal instructions. Matching is case-insensitive.
func checkLeaks(output string) []leakMatch {
	// Quick short-circuit: if the output is very short it is unlikely to
	// contain a prompt leak.
	if len(strings.TrimSpace(output)) < 10 {
		return nil
	}

	var matches []leakMatch
	for _, entry := range leakPatterns {
		locs := entry.re.FindAllStringIndex(output, -1)
		for _, loc := range locs {
			matches = append(matches, leakMatch{
				pattern:     entry.re.String(),
				match:       output[loc[0]:loc[1]],
				start:       loc[0],
				end:         loc[1],
				description: entry.description,
				severity:    entry.severity,
			})
		}
	}
	return matches
}
