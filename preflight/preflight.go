// Package preflight provides an automated red-team test suite for promptsec
// protectors. It ships a curated corpus of prompt-injection attacks spanning
// every standard threat category and runs them against a configured Protector,
// producing a structured vulnerability report with detection rates, false
// positive rates, and per-category breakdowns.
//
// Basic usage:
//
//	runner := preflight.NewRunner(preflight.Config{
//	    Protector: myProtector,
//	})
//	report := runner.Run()
//	fmt.Println(report)
package preflight

import (
	"time"

	pp "github.com/danielthedm/promptsec"
)

// Config controls which protector is tested, which threat categories are
// in scope, and how much detail is emitted.
type Config struct {
	// Protector is the promptsec Protector instance under test.
	Protector *pp.Protector

	// Categories limits the run to the listed threat types. A nil or empty
	// slice means all categories are tested.
	Categories []pp.ThreatType

	// Verbose, when true, causes the runner to retain full Result objects
	// in every AttackResult. When false the Result field is still populated
	// but callers should not rely on Metadata being complete.
	Verbose bool
}

// Runner holds the configuration and attack corpus for a preflight run.
type Runner struct {
	config  Config
	attacks []Attack
}

// NewRunner creates a Runner pre-loaded with the DefaultAttacks corpus.
// Additional attacks may be added with AddAttacks before calling Run.
func NewRunner(config Config) *Runner {
	return &Runner{
		config:  config,
		attacks: DefaultAttacks(),
	}
}

// AddAttacks appends custom attacks to the corpus. They will be included in
// the next call to Run alongside the built-in attacks.
func (r *Runner) AddAttacks(attacks ...Attack) {
	r.attacks = append(r.attacks, attacks...)
}

// Run executes every attack in the corpus against the configured Protector
// and returns a Report with aggregate and per-attack results.
func (r *Runner) Run() *Report {
	start := time.Now()

	categoryFilter := make(map[pp.ThreatType]bool, len(r.config.Categories))
	for _, c := range r.config.Categories {
		categoryFilter[c] = true
	}
	filterActive := len(categoryFilter) > 0

	report := &Report{
		ByCategory: make(map[pp.ThreatType]*CategoryResult),
	}

	for _, atk := range r.attacks {
		// If a category filter is active, skip attacks that do not match.
		// Benign inputs (empty category) are always included so that false-
		// positive measurement is not silently dropped.
		if filterActive && atk.Category != "" && !categoryFilter[atk.Category] {
			continue
		}

		result := r.config.Protector.Analyze(atk.Input)
		detected := !result.Safe

		ar := AttackResult{
			Attack:   atk,
			Result:   result,
			Detected: detected,
			Expected: atk.Expected,
			Correct:  detected == atk.Expected,
		}
		report.Details = append(report.Details, ar)
		report.TotalAttacks++

		// Aggregate counts.
		if atk.Expected {
			// This is a real attack.
			if detected {
				report.Detected++
			} else {
				report.Missed++
			}

			// Per-category tracking.
			cr, ok := report.ByCategory[atk.Category]
			if !ok {
				cr = &CategoryResult{}
				report.ByCategory[atk.Category] = cr
			}
			cr.Total++
			if detected {
				cr.Detected++
			} else {
				cr.Missed++
			}
		} else {
			// This is a benign input.
			if detected {
				report.FalsePositives++
			}
		}
	}

	// Compute rates.
	totalMalicious := report.Detected + report.Missed
	if totalMalicious > 0 {
		report.DetectionRate = float64(report.Detected) / float64(totalMalicious)
	}

	totalBenign := 0
	for _, d := range report.Details {
		if !d.Expected {
			totalBenign++
		}
	}
	if totalBenign > 0 {
		report.FalsePositiveRate = float64(report.FalsePositives) / float64(totalBenign)
	}

	// Per-category rates.
	for _, cr := range report.ByCategory {
		if cr.Total > 0 {
			cr.Rate = float64(cr.Detected) / float64(cr.Total)
		}
	}

	report.Duration = time.Since(start)

	return report
}
