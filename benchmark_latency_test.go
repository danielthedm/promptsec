//go:build functional

package promptsec_test

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"testing"
	"time"

	ps "github.com/danielthedm/promptsec"
)

type latencyResult struct {
	name           string
	calls          int
	totalDuration  time.Duration
	durations      []time.Duration
	detected       int
	totalInject    int
	falsePositives int
	totalBenign    int
}

func (r *latencyResult) avg() time.Duration {
	if r.calls == 0 {
		return 0
	}
	return r.totalDuration / time.Duration(r.calls)
}

func (r *latencyResult) percentile(p float64) time.Duration {
	if len(r.durations) == 0 {
		return 0
	}
	idx := int(math.Ceil(p/100*float64(len(r.durations)))) - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= len(r.durations) {
		idx = len(r.durations) - 1
	}
	return r.durations[idx]
}

func (r *latencyResult) tpr() float64 {
	if r.totalInject == 0 {
		return 0
	}
	return float64(r.detected) / float64(r.totalInject)
}

func (r *latencyResult) fpr() float64 {
	if r.totalBenign == 0 {
		return 0
	}
	return float64(r.falsePositives) / float64(r.totalBenign)
}

func runLatencyBenchmark(entries []benchmarkEntry, name string, protector *ps.Protector) *latencyResult {
	r := &latencyResult{
		name:      name,
		durations: make([]time.Duration, 0, len(entries)),
	}

	for _, e := range entries {
		start := time.Now()
		result := protector.Analyze(e.Text)
		d := time.Since(start)

		r.calls++
		r.totalDuration += d
		r.durations = append(r.durations, d)

		if e.Label == 1 {
			r.totalInject++
			if !result.Safe {
				r.detected++
			}
		} else {
			r.totalBenign++
			if !result.Safe {
				r.falsePositives++
			}
		}
	}

	sort.Slice(r.durations, func(i, j int) bool {
		return r.durations[i] < r.durations[j]
	})

	return r
}

func fmtDur(d time.Duration) string {
	us := float64(d.Nanoseconds()) / 1000
	if us < 1000 {
		return fmt.Sprintf("%.0fus", us)
	}
	return fmt.Sprintf("%.1fms", us/1000)
}

func TestLatencyReport(t *testing.T) {
	entries := loadDeepsetDataset(t)

	presets := []struct {
		name      string
		protector *ps.Protector
	}{
		{"Strict", ps.Strict()},
		{"Moderate", ps.Moderate()},
		{"Lenient", ps.Lenient()},
	}

	results := make([]*latencyResult, len(presets))
	for i, p := range presets {
		results[i] = runLatencyBenchmark(entries, p.name, p.protector)
	}

	var b strings.Builder

	b.WriteString("\n")
	b.WriteString("## Performance\n\n")
	b.WriteString(fmt.Sprintf("Measured on %d inputs (%d injections, %d benign) from the deepset prompt-injections dataset.\n\n",
		len(entries), countLabel(entries, 1), countLabel(entries, 0)))

	b.WriteString("| Preset | Avg | p50 | p95 | p99 | TPR | FPR |\n")
	b.WriteString("|--------|-----|-----|-----|-----|-----|-----|\n")

	for _, r := range results {
		b.WriteString(fmt.Sprintf("| %s | %s | %s | %s | %s | %.1f%% | %.1f%% |\n",
			r.name,
			fmtDur(r.avg()),
			fmtDur(r.percentile(50)),
			fmtDur(r.percentile(95)),
			fmtDur(r.percentile(99)),
			r.tpr()*100,
			r.fpr()*100,
		))
	}

	b.WriteString("\n")
	b.WriteString(fmt.Sprintf("Zero external API calls. All detection runs locally in-process.\n"))

	t.Log(b.String())
}
