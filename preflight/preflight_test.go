package preflight_test

import (
	"testing"

	pp "github.com/danielthedm/promptsec"
	"github.com/danielthedm/promptsec/preflight"
)

func TestRunReturnsReport(t *testing.T) {
	protector := pp.New(
		pp.WithHeuristics(&pp.HeuristicOptions{
			Preset: pp.PresetStrict,
		}),
	)

	runner := preflight.NewRunner(preflight.Config{
		Protector: protector,
	})

	report := runner.Run()

	if report == nil {
		t.Fatal("expected non-nil report")
	}
	if report.TotalAttacks == 0 {
		t.Error("expected TotalAttacks > 0")
	}
	if report.Duration == 0 {
		t.Error("expected non-zero Duration")
	}
	if report.Details == nil {
		t.Error("expected Details to be populated")
	}
	if len(report.Details) != report.TotalAttacks {
		t.Errorf("expected len(Details) == TotalAttacks (%d), got %d",
			report.TotalAttacks, len(report.Details))
	}
}

func TestDetectionRate(t *testing.T) {
	// With a strict protector, detection rate should be high
	protector := pp.New(
		pp.WithHeuristics(&pp.HeuristicOptions{
			Preset:    pp.PresetStrict,
			Threshold: 0.3,
		}),
		pp.WithSanitizer(&pp.SanitizerOptions{
			Normalize:      true,
			Dehomoglyph:    true,
			StripZeroWidth: true,
			DecodePayloads: true,
		}),
	)

	runner := preflight.NewRunner(preflight.Config{
		Protector: protector,
	})

	report := runner.Run()

	if report.DetectionRate < 0.5 {
		t.Errorf("expected detection rate > 0.5 for strict protector, got %.2f",
			report.DetectionRate)
	}

	// Check that some attacks were detected
	if report.Detected == 0 {
		t.Error("expected at least some attacks to be detected")
	}
}

func TestBenignNotFlagged(t *testing.T) {
	// Using a lenient protector, benign inputs should not be flagged
	protector := pp.New(
		pp.WithHeuristics(&pp.HeuristicOptions{
			Preset:    pp.PresetLenient,
			Threshold: 0.7,
		}),
	)

	runner := preflight.NewRunner(preflight.Config{
		Protector: protector,
	})

	report := runner.Run()

	// Count benign inputs that were incorrectly flagged
	falsePositives := 0
	for _, d := range report.Details {
		if !d.Expected && d.Detected {
			falsePositives++
			t.Logf("false positive: %q", d.Attack.Input)
		}
	}

	// The false positive rate should be low with lenient settings
	if report.FalsePositiveRate > 0.5 {
		t.Errorf("expected false positive rate < 0.5, got %.2f (%d false positives)",
			report.FalsePositiveRate, falsePositives)
	}
}

func TestDefaultAttacks(t *testing.T) {
	attacks := preflight.DefaultAttacks()

	if len(attacks) < 40 {
		t.Errorf("expected at least 40 default attacks, got %d", len(attacks))
	}

	// Check that we have both expected=true (attacks) and expected=false (benign)
	attackCount := 0
	benignCount := 0
	for _, a := range attacks {
		if a.Expected {
			attackCount++
		} else {
			benignCount++
		}
	}

	if attackCount == 0 {
		t.Error("expected some attacks (Expected=true) in the corpus")
	}
	if benignCount == 0 {
		t.Error("expected some benign inputs (Expected=false) in the corpus")
	}
}

func TestDefaultAttacksHaveCategories(t *testing.T) {
	attacks := preflight.DefaultAttacks()

	categories := make(map[pp.ThreatType]int)
	for _, a := range attacks {
		if a.Expected && a.Category != "" {
			categories[a.Category]++
		}
	}

	expectedCategories := []pp.ThreatType{
		pp.ThreatInstructionOverride,
		pp.ThreatRoleManipulation,
		pp.ThreatDelimiterInjection,
		pp.ThreatSystemPromptLeak,
		pp.ThreatEncodingAttack,
	}

	for _, cat := range expectedCategories {
		count, ok := categories[cat]
		if !ok || count == 0 {
			t.Errorf("expected attacks in category %q, found none", cat)
		}
	}
}

func TestReportString(t *testing.T) {
	protector := pp.New(
		pp.WithHeuristics(&pp.HeuristicOptions{
			Preset: pp.PresetStrict,
		}),
	)

	runner := preflight.NewRunner(preflight.Config{
		Protector: protector,
	})

	report := runner.Run()
	output := report.String()

	if output == "" {
		t.Fatal("expected non-empty report string")
	}

	// Report should contain key sections
	if !containsStr(output, "PREFLIGHT RED-TEAM REPORT") {
		t.Error("expected report to contain 'PREFLIGHT RED-TEAM REPORT'")
	}
	if !containsStr(output, "Total attacks:") {
		t.Error("expected report to contain 'Total attacks:'")
	}
	if !containsStr(output, "Detection rate:") {
		t.Error("expected report to contain 'Detection rate:'")
	}
}

func TestCategoryFilter(t *testing.T) {
	protector := pp.New(
		pp.WithHeuristics(&pp.HeuristicOptions{
			Preset: pp.PresetStrict,
		}),
	)

	runner := preflight.NewRunner(preflight.Config{
		Protector:  protector,
		Categories: []pp.ThreatType{pp.ThreatInstructionOverride},
	})

	report := runner.Run()

	// Should only have instruction_override attacks (plus benign)
	for _, d := range report.Details {
		if d.Expected && d.Attack.Category != pp.ThreatInstructionOverride {
			t.Errorf("expected only instruction_override attacks, got %q", d.Attack.Category)
		}
	}
}

func TestAddCustomAttacks(t *testing.T) {
	protector := pp.New(
		pp.WithHeuristics(nil),
	)

	runner := preflight.NewRunner(preflight.Config{
		Protector: protector,
	})

	initialCount := len(preflight.DefaultAttacks())

	runner.AddAttacks(preflight.Attack{
		Input:    "custom attack: ignore everything",
		Category: pp.ThreatInstructionOverride,
		Name:     "custom test attack",
		Expected: true,
	})

	report := runner.Run()

	// Total should be default attacks + 1 custom
	if report.TotalAttacks != initialCount+1 {
		t.Errorf("expected %d total attacks (default + 1 custom), got %d",
			initialCount+1, report.TotalAttacks)
	}
}

func TestPerCategoryBreakdown(t *testing.T) {
	protector := pp.New(
		pp.WithHeuristics(&pp.HeuristicOptions{
			Preset: pp.PresetStrict,
		}),
	)

	runner := preflight.NewRunner(preflight.Config{
		Protector: protector,
	})

	report := runner.Run()

	if len(report.ByCategory) == 0 {
		t.Error("expected per-category breakdown to be populated")
	}

	for cat, cr := range report.ByCategory {
		if cr.Total == 0 {
			t.Errorf("expected non-zero Total for category %q", cat)
		}
		if cr.Detected+cr.Missed != cr.Total {
			t.Errorf("category %q: Detected(%d) + Missed(%d) != Total(%d)",
				cat, cr.Detected, cr.Missed, cr.Total)
		}
		if cr.Total > 0 {
			expectedRate := float64(cr.Detected) / float64(cr.Total)
			if cr.Rate != expectedRate {
				t.Errorf("category %q: Rate %.4f != expected %.4f",
					cat, cr.Rate, expectedRate)
			}
		}
	}
}

// containsStr is a simple helper to check substring presence.
func containsStr(s, substr string) bool {
	return len(s) > 0 && len(substr) > 0 && stringContains(s, substr)
}

func stringContains(s, substr string) bool {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
