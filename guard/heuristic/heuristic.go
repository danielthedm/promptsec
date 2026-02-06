// Package heuristic provides a prompt-injection detection guard that uses
// compiled regular-expression patterns, encoding analysis, and fuzzy matching
// to identify threats in user input.
package heuristic

import (
	"regexp"

	"github.com/danielthedm/promptsec/internal/core"
)

// Options configures the heuristic guard.
type Options struct {
	// Preset selects the severity threshold for built-in patterns.
	//   PresetStrict   - all patterns (severity >= 0.0)
	//   PresetModerate - severity >= 0.5
	//   PresetLenient  - severity >= 0.7
	Preset core.Preset

	// Threshold overrides the preset-based severity floor. When non-zero
	// only patterns whose severity >= Threshold are evaluated.
	Threshold float64

	// CustomPatterns are additional regex patterns to evaluate alongside
	// the built-in set.
	CustomPatterns []PatternEntry

	// HaltOnDetect causes the guard to call ctx.Halt() as soon as any
	// threat is detected, preventing downstream guards from executing.
	HaltOnDetect bool
}

// Guard implements core.Guard using heuristic pattern matching.
type Guard struct {
	opts     Options
	patterns []patternEntry
}

// Compile-time interface check.
var _ core.Guard = (*Guard)(nil)

// New creates a new heuristic Guard from the given options. If opts is nil a
// zero-value (PresetStrict, no custom patterns, no halt) is used.
func New(opts *Options) *Guard {
	if opts == nil {
		opts = &Options{}
	}

	g := &Guard{opts: *opts}
	g.patterns = g.buildPatterns()
	return g
}

// Name returns the guard identifier.
func (g *Guard) Name() string { return "heuristic" }

// Execute runs all selected patterns, encoding detectors, and fuzzy matchers
// against ctx.Input. Detected threats are added to the context. If
// HaltOnDetect is set the context is halted on the first match. Finally the
// next guard in the chain is invoked (unless halted).
func (g *Guard) Execute(ctx *core.Context, next core.NextFn) {
	input := ctx.Input
	detected := false

	// 1. Run compiled regex patterns.
	for i := range g.patterns {
		p := &g.patterns[i]
		loc := p.re.FindStringIndex(input)
		if loc == nil {
			continue
		}

		ctx.AddThreat(core.Threat{
			Type:     p.threatType,
			Severity: p.severity,
			Message:  p.description,
			Guard:    "heuristic",
			Match:    input[loc[0]:loc[1]],
			Start:    loc[0],
			End:      loc[1],
		})
		detected = true

		if g.opts.HaltOnDetect {
			ctx.Halt()
			return
		}
	}

	// 2. Run encoding attack detection.
	for _, t := range detectEncodingAttacks(input) {
		ctx.AddThreat(t)
		detected = true

		if g.opts.HaltOnDetect {
			ctx.Halt()
			return
		}
	}

	// 3. Run fuzzy / typoglycemia matching.
	matched := fuzzyMatch(input)
	if len(matched) >= 2 {
		// Two or more critical keywords fuzzy-matched is suspicious.
		ctx.AddThreat(core.Threat{
			Type:     core.ThreatInstructionOverride,
			Severity: 0.65,
			Message:  "fuzzy match detected multiple injection-related keywords (possible typo evasion)",
			Guard:    "heuristic",
		})
		detected = true

		if g.opts.HaltOnDetect {
			ctx.Halt()
			return
		}
	}

	// Store match metadata for downstream guards.
	if detected {
		ctx.SetMeta("heuristic.detected", true)
	}

	// Continue the chain.
	if !ctx.Halted {
		next(ctx)
	}
}

// buildPatterns filters the default pattern set according to the configured
// preset/threshold and appends any custom patterns.
func (g *Guard) buildPatterns() []patternEntry {
	minSeverity := g.minSeverity()

	filtered := make([]patternEntry, 0, len(defaultPatterns))
	for _, p := range defaultPatterns {
		if p.severity >= minSeverity {
			filtered = append(filtered, p)
		}
	}

	// Compile and append custom patterns.
	for _, cp := range g.opts.CustomPatterns {
		sev := cp.Severity
		if sev < minSeverity {
			continue
		}
		tt := cp.ThreatType
		if tt == "" {
			tt = core.ThreatCustom
		}
		filtered = append(filtered, patternEntry{
			re:          regexp.MustCompile(cp.Pattern),
			threatType:  tt,
			severity:    sev,
			description: cp.Description,
		})
	}

	return filtered
}

// minSeverity returns the minimum severity based on the option's Threshold or
// Preset.
func (g *Guard) minSeverity() float64 {
	if g.opts.Threshold > 0 {
		return g.opts.Threshold
	}
	switch g.opts.Preset {
	case core.PresetModerate:
		return 0.5
	case core.PresetLenient:
		return 0.7
	default: // PresetStrict
		return 0.0
	}
}
