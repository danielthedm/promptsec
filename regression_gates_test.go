//go:build functional

package promptsec_test

import (
	"math"
	"sort"
	"testing"
	"time"

	ps "github.com/danielthedm/promptsec"
)

// ---------------------------------------------------------------------------
// 5. TPR/FPR Regression Gates (deepset dataset)
// ---------------------------------------------------------------------------

// regressionTPR is a helper that runs the given protector against the deepset
// dataset and asserts that the true-positive rate meets the minimum threshold.
func regressionTPR(t *testing.T, name string, protector *ps.Protector, minTPR float64) {
	t.Helper()
	entries := loadDeepsetDataset(t)
	r := runBenchmark(entries, protector)
	logBenchResult(t, name, r)

	if r.TPR() < minTPR {
		t.Errorf("%s TPR regression: got %.1f%%, want >= %.1f%%",
			name, r.TPR()*100, minTPR*100)
	}
}

func TestRegression_TPR_Strict(t *testing.T) {
	regressionTPR(t, "Strict", ps.Strict(), 0.60)
}

func TestRegression_TPR_Moderate(t *testing.T) {
	regressionTPR(t, "Moderate", ps.Moderate(), 0.55)
}

func TestRegression_TPR_Lenient(t *testing.T) {
	regressionTPR(t, "Lenient", ps.Lenient(), 0.50)
}

func TestRegression_FPR_AllPresets(t *testing.T) {
	entries := loadDeepsetDataset(t)

	presets := []struct {
		name      string
		protector *ps.Protector
	}{
		{"Strict", ps.Strict()},
		{"Moderate", ps.Moderate()},
		{"Lenient", ps.Lenient()},
	}

	for _, tc := range presets {
		t.Run(tc.name, func(t *testing.T) {
			r := runBenchmark(entries, tc.protector)
			logBenchResult(t, tc.name, r)

			if r.FPR() != 0.0 {
				t.Errorf("%s FPR regression: got %.2f%%, want 0.00%%",
					tc.name, r.FPR()*100)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 6. Latency Regression Gates (p99)
// ---------------------------------------------------------------------------

// shortInputs returns the subset of dataset entries whose text length is
// at most maxLen bytes. This keeps the latency gate focused on typical
// user-input sizes rather than outlier-length payloads.
func shortInputs(entries []benchmarkEntry, maxLen int) []benchmarkEntry {
	var out []benchmarkEntry
	for _, e := range entries {
		if len(e.Text) <= maxLen {
			out = append(out, e)
		}
	}
	return out
}

// p99Duration measures the p99 latency of protector.Analyze over the given
// inputs. It returns sorted durations and the computed p99 value.
func p99Duration(t *testing.T, protector *ps.Protector, inputs []benchmarkEntry) ([]time.Duration, time.Duration) {
	t.Helper()
	durations := make([]time.Duration, 0, len(inputs))
	for _, e := range inputs {
		start := time.Now()
		protector.Analyze(e.Text)
		durations = append(durations, time.Since(start))
	}
	sort.Slice(durations, func(i, j int) bool {
		return durations[i] < durations[j]
	})

	idx := int(math.Ceil(0.99*float64(len(durations)))) - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= len(durations) {
		idx = len(durations) - 1
	}
	return durations, durations[idx]
}

func TestRegression_Latency_Strict(t *testing.T) {
	entries := loadDeepsetDataset(t)
	inputs := shortInputs(entries, 512)
	if len(inputs) == 0 {
		t.Skip("no short inputs in dataset")
	}

	_, p99 := p99Duration(t, ps.Strict(), inputs)
	t.Logf("Strict p99 latency: %v (over %d short inputs)", p99, len(inputs))

	const limit = 5 * time.Millisecond
	if p99 > limit {
		t.Errorf("Strict p99 latency regression: got %v, want <= %v", p99, limit)
	}
}

func TestRegression_Latency_Moderate(t *testing.T) {
	entries := loadDeepsetDataset(t)
	inputs := shortInputs(entries, 512)
	if len(inputs) == 0 {
		t.Skip("no short inputs in dataset")
	}

	_, p99 := p99Duration(t, ps.Moderate(), inputs)
	t.Logf("Moderate p99 latency: %v (over %d short inputs)", p99, len(inputs))

	const limit = 5 * time.Millisecond
	if p99 > limit {
		t.Errorf("Moderate p99 latency regression: got %v, want <= %v", p99, limit)
	}
}

func TestRegression_Latency_Lenient(t *testing.T) {
	entries := loadDeepsetDataset(t)
	inputs := shortInputs(entries, 512)
	if len(inputs) == 0 {
		t.Skip("no short inputs in dataset")
	}

	_, p99 := p99Duration(t, ps.Lenient(), inputs)
	t.Logf("Lenient p99 latency: %v (over %d short inputs)", p99, len(inputs))

	const limit = 3 * time.Millisecond
	if p99 > limit {
		t.Errorf("Lenient p99 latency regression: got %v, want <= %v", p99, limit)
	}
}
