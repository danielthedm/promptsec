package preflight

import (
	"fmt"
	"strings"
	"time"

	pp "github.com/danielthedm/promptsec"
)

// Report is the result of a preflight red-team run. It contains aggregate
// metrics, per-category breakdowns, and individual attack results so that
// callers can programmatically inspect coverage gaps.
type Report struct {
	TotalAttacks      int
	Detected          int
	Missed            int
	FalsePositives    int
	DetectionRate     float64
	FalsePositiveRate float64
	ByCategory        map[pp.ThreatType]*CategoryResult
	Duration          time.Duration
	Details           []AttackResult
}

// CategoryResult holds detection metrics for a single threat category.
type CategoryResult struct {
	Total    int
	Detected int
	Missed   int
	Rate     float64
}

// AttackResult pairs a single attack with the protector's response and
// whether the outcome matched expectations.
type AttackResult struct {
	Attack   Attack
	Result   *pp.Result
	Detected bool
	Expected bool
	Correct  bool
}

// String produces a human-readable preflight report suitable for printing
// to a terminal or writing to a log file.
func (r *Report) String() string {
	var b strings.Builder

	b.WriteString("=============================================================\n")
	b.WriteString("                   PREFLIGHT RED-TEAM REPORT                  \n")
	b.WriteString("=============================================================\n\n")

	// ── Overall summary ─────────────────────────────────────────────────
	fmt.Fprintf(&b, "Total attacks:      %d\n", r.TotalAttacks)
	fmt.Fprintf(&b, "Detected:           %d\n", r.Detected)
	fmt.Fprintf(&b, "Missed:             %d\n", r.Missed)
	fmt.Fprintf(&b, "False positives:    %d\n", r.FalsePositives)
	fmt.Fprintf(&b, "Detection rate:     %.1f%%\n", r.DetectionRate*100)
	fmt.Fprintf(&b, "False positive rate: %.1f%%\n", r.FalsePositiveRate*100)
	fmt.Fprintf(&b, "Duration:           %s\n", r.Duration.Round(time.Millisecond))

	// ── Per-category breakdown ──────────────────────────────────────────
	if len(r.ByCategory) > 0 {
		b.WriteString("\n-------------------------------------------------------------\n")
		b.WriteString("  Per-Category Breakdown\n")
		b.WriteString("-------------------------------------------------------------\n")

		categories := []pp.ThreatType{
			pp.ThreatInstructionOverride,
			pp.ThreatRoleManipulation,
			pp.ThreatDelimiterInjection,
			pp.ThreatSystemPromptLeak,
			pp.ThreatEncodingAttack,
		}

		for _, cat := range categories {
			cr, ok := r.ByCategory[cat]
			if !ok {
				continue
			}
			fmt.Fprintf(&b, "\n  %-25s  %d/%d detected  (%.1f%%)\n",
				string(cat), cr.Detected, cr.Total, cr.Rate*100)
			if cr.Missed > 0 {
				fmt.Fprintf(&b, "    Missed: %d\n", cr.Missed)
			}
		}

		// Print any remaining categories not in the predefined list.
		for cat, cr := range r.ByCategory {
			found := false
			for _, c := range categories {
				if cat == c {
					found = true
					break
				}
			}
			if found {
				continue
			}
			fmt.Fprintf(&b, "\n  %-25s  %d/%d detected  (%.1f%%)\n",
				string(cat), cr.Detected, cr.Total, cr.Rate*100)
		}
	}

	// ── Missed attacks ──────────────────────────────────────────────────
	var missed []AttackResult
	for _, d := range r.Details {
		if d.Expected && !d.Detected {
			missed = append(missed, d)
		}
	}
	if len(missed) > 0 {
		b.WriteString("\n-------------------------------------------------------------\n")
		b.WriteString("  Missed Attacks\n")
		b.WriteString("-------------------------------------------------------------\n")
		for i, m := range missed {
			fmt.Fprintf(&b, "\n  %d. [%s] %s\n", i+1, m.Attack.Category, m.Attack.Name)
			input := m.Attack.Input
			if len(input) > 80 {
				input = input[:77] + "..."
			}
			fmt.Fprintf(&b, "     Input: %q\n", input)
		}
	}

	// ── False positives ─────────────────────────────────────────────────
	var fps []AttackResult
	for _, d := range r.Details {
		if !d.Expected && d.Detected {
			fps = append(fps, d)
		}
	}
	if len(fps) > 0 {
		b.WriteString("\n-------------------------------------------------------------\n")
		b.WriteString("  False Positives\n")
		b.WriteString("-------------------------------------------------------------\n")
		for i, fp := range fps {
			fmt.Fprintf(&b, "\n  %d. %s\n", i+1, fp.Attack.Name)
			input := fp.Attack.Input
			if len(input) > 80 {
				input = input[:77] + "..."
			}
			fmt.Fprintf(&b, "     Input: %q\n", input)
			if fp.Result != nil && len(fp.Result.Threats) > 0 {
				for _, t := range fp.Result.Threats {
					fmt.Fprintf(&b, "     Flagged: [%s] %s (severity=%.2f)\n",
						t.Type, t.Message, t.Severity)
				}
			}
		}
	}

	// ── Footer ──────────────────────────────────────────────────────────
	if len(missed) == 0 && len(fps) == 0 {
		b.WriteString("\n-------------------------------------------------------------\n")
		b.WriteString("  All attacks detected. No false positives. Looking good!\n")
	}

	b.WriteString("\n=============================================================\n")

	return b.String()
}
