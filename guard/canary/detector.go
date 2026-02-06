package canary

import (
	"strings"

	"github.com/danielthedm/promptsec/internal/core"
)

// minPartialLen is the minimum substring length considered meaningful when
// performing partial-match detection. Shorter fragments are too likely to
// produce false positives.
const minPartialLen = 8

// DetectorGuard is an output guard that scans LLM output for the presence of
// a canary token that was previously injected by Guard. A match indicates the
// model is leaking input data.
type DetectorGuard struct {
	opts Options
}

// NewDetector creates a canary leakage detector. If opts is nil, defaults are
// used (the options are only needed so the detector can share configuration
// with the injection guard; the actual token is read from ctx.Metadata).
func NewDetector(opts *Options) *DetectorGuard {
	o := Options{
		Format: core.CanaryHex,
		Length: defaultLength,
		Prefix: defaultPrefix,
	}
	if opts != nil {
		o = *opts
		o.defaults()
	}
	return &DetectorGuard{opts: o}
}

// Name returns the guard identifier.
func (g *DetectorGuard) Name() string { return "canary-detector" }

// IsOutputGuard marks this guard as an output-phase guard. It should be
// evaluated against LLM output rather than user input.
func (g *DetectorGuard) IsOutputGuard() bool { return true }

// Execute checks ctx.Input (the LLM output being validated) for the canary
// token stored in ctx.Metadata by the injection guard. If any form of the
// token is detected, a ThreatCanaryLeak is added to the context.
func (g *DetectorGuard) Execute(ctx *core.Context, next core.NextFn) {
	raw, ok := ctx.GetMeta(metaKeyToken)
	if !ok {
		// No canary was injected; nothing to detect.
		next(ctx)
		return
	}

	token, ok := raw.(string)
	if !ok || token == "" {
		next(ctx)
		return
	}

	output := ctx.Input // In output-guard phase, Input holds the LLM output.

	if matched, start, end := detectLeak(output, token); matched {
		ctx.AddThreat(core.Threat{
			Type:     core.ThreatCanaryLeak,
			Severity: 1.0,
			Message:  "canary token detected in model output, possible data exfiltration",
			Guard:    g.Name(),
			Match:    output[start:end],
			Start:    start,
			End:      end,
		})
	}

	next(ctx)
}

// detectLeak returns true and the span [start, end) of the first match if the
// token (or a recognisable fragment) appears in output. It tries four
// strategies in order of specificity.
func detectLeak(output, token string) (matched bool, start, end int) {
	// 1. Exact match.
	if idx := strings.Index(output, token); idx >= 0 {
		return true, idx, idx + len(token)
	}

	// 2. Case-insensitive match.
	lowerOut := strings.ToLower(output)
	lowerTok := strings.ToLower(token)
	if idx := strings.Index(lowerOut, lowerTok); idx >= 0 {
		return true, idx, idx + len(token)
	}

	// 3. Obfuscated match -- strip spaces, dashes, and underscores.
	normOut := stripNoise(lowerOut)
	normTok := stripNoise(lowerTok)
	if idx := strings.Index(normOut, normTok); idx >= 0 {
		// Map back to an approximate position in the original output.
		// The exact offsets may differ because noise characters were
		// removed, so we use the normalised index as a best-effort.
		return true, idx, idx + len(normTok)
	}

	// 4. Partial match -- look for any 8+ char substring of the token.
	if len(normTok) >= minPartialLen {
		subLen := len(normTok)
		for off := 0; off+subLen <= len(normTok); off++ {
			sub := normTok[off : off+subLen]
			if idx := strings.Index(normOut, sub); idx >= 0 {
				return true, idx, idx + len(sub)
			}
		}
	}

	return false, 0, 0
}

// stripNoise removes spaces, dashes, and underscores from s.
func stripNoise(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != ' ' && c != '-' && c != '_' {
			b.WriteByte(c)
		}
	}
	return b.String()
}
