//go:build functional

package promptsec_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	ps "github.com/danielthedm/promptsec"
)

type benchmarkEntry struct {
	Text  string `json:"text"`
	Label int    `json:"label"`
}

func loadDeepsetDataset(t *testing.T) []benchmarkEntry {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "benchmark", "deepset_prompt_injections.json"))
	if err != nil {
		t.Fatalf("failed to read deepset dataset: %v", err)
	}
	var entries []benchmarkEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		t.Fatalf("failed to parse deepset dataset: %v", err)
	}
	return entries
}

const safeguardCachePath = "testdata/benchmark/.safeguard_cache.json"

func fetchSafeGuardDataset(t *testing.T) []benchmarkEntry {
	t.Helper()

	// Try cache first
	if data, err := os.ReadFile(safeguardCachePath); err == nil {
		var entries []benchmarkEntry
		if err := json.Unmarshal(data, &entries); err == nil && len(entries) > 0 {
			t.Logf("loaded %d entries from cache", len(entries))
			return entries
		}
	}

	var all []benchmarkEntry
	for _, split := range []string{"train", "test"} {
		offset := 0
		for {
			url := fmt.Sprintf(
				"https://datasets-server.huggingface.co/rows?dataset=xTRam1/safe-guard-prompt-injection&config=default&split=%s&offset=%d&length=100",
				split, offset,
			)
			resp, err := http.Get(url)
			if err != nil {
				t.Skipf("network unavailable, skipping safe-guard benchmark: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				t.Skipf("HuggingFace API returned %d, skipping safe-guard benchmark", resp.StatusCode)
			}

			var result struct {
				Rows []struct {
					Row struct {
						Text  string `json:"text"`
						Label int    `json:"label"`
					} `json:"row"`
				} `json:"rows"`
			}
			if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
				t.Skipf("failed to decode safe-guard response: %v", err)
			}

			if len(result.Rows) == 0 {
				break
			}

			for _, r := range result.Rows {
				all = append(all, benchmarkEntry{
					Text:  r.Row.Text,
					Label: r.Row.Label,
				})
			}

			offset += 100
			if len(result.Rows) < 100 {
				break
			}
		}
	}

	if len(all) == 0 {
		t.Skip("no data fetched from safe-guard dataset")
	}

	t.Logf("fetched %d entries from HuggingFace", len(all))

	// Cache for subsequent runs
	if data, err := json.Marshal(all); err == nil {
		_ = os.MkdirAll(filepath.Dir(safeguardCachePath), 0o755)
		_ = os.WriteFile(safeguardCachePath, data, 0o644)
	}

	return all
}

type benchResult struct {
	TotalInjections int
	TotalBenign     int
	Detected        int
	FalsePositives  int
}

func (r benchResult) TPR() float64 {
	if r.TotalInjections == 0 {
		return 0
	}
	return float64(r.Detected) / float64(r.TotalInjections)
}

func (r benchResult) FPR() float64 {
	if r.TotalBenign == 0 {
		return 0
	}
	return float64(r.FalsePositives) / float64(r.TotalBenign)
}

func runBenchmark(entries []benchmarkEntry, protector *ps.Protector) benchResult {
	var res benchResult
	for _, e := range entries {
		result := protector.Analyze(e.Text)
		if e.Label == 1 {
			res.TotalInjections++
			if !result.Safe {
				res.Detected++
			}
		} else {
			res.TotalBenign++
			if !result.Safe {
				res.FalsePositives++
			}
		}
	}
	return res
}

func logBenchResult(t *testing.T, name string, r benchResult) {
	t.Helper()
	t.Logf("%s: detected %d/%d injections (TPR=%.1f%%), FP %d/%d benign (FPR=%.1f%%)",
		name, r.Detected, r.TotalInjections, r.TPR()*100,
		r.FalsePositives, r.TotalBenign, r.FPR()*100)
}

func TestBenchmarkDeepset(t *testing.T) {
	entries := loadDeepsetDataset(t)
	t.Logf("loaded %d entries (injections: %d, benign: %d)",
		len(entries),
		countLabel(entries, 1),
		countLabel(entries, 0))

	tests := []struct {
		name      string
		protector *ps.Protector
		minTPR    float64
		maxFPR    float64
	}{
		{"Strict", ps.Strict(), 0.55, 0.02},
		{"Moderate", ps.Moderate(), 0.55, 0.02},
		{"Lenient", ps.Lenient(), 0.50, 0.02},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := runBenchmark(entries, tc.protector)
			logBenchResult(t, tc.name, r)

			if r.TPR() < tc.minTPR {
				t.Errorf("%s TPR %.1f%% below threshold %.1f%%", tc.name, r.TPR()*100, tc.minTPR*100)
			}
			if r.FPR() > tc.maxFPR {
				t.Errorf("%s FPR %.1f%% above threshold %.1f%%", tc.name, r.FPR()*100, tc.maxFPR*100)
			}
		})
	}
}

func TestBenchmarkSafeGuard(t *testing.T) {
	entries := fetchSafeGuardDataset(t)
	t.Logf("loaded %d entries (injections: %d, benign: %d)",
		len(entries),
		countLabel(entries, 1),
		countLabel(entries, 0))

	protector := ps.Strict()
	r := runBenchmark(entries, protector)
	logBenchResult(t, "Strict (safe-guard)", r)

	if r.TPR() < 0.30 {
		t.Errorf("Strict TPR %.1f%% below threshold 30.0%%", r.TPR()*100)
	}
	if r.FPR() > 0.10 {
		t.Errorf("Strict FPR %.1f%% above threshold 10.0%%", r.FPR()*100)
	}
}

func countLabel(entries []benchmarkEntry, label int) int {
	n := 0
	for _, e := range entries {
		if e.Label == label {
			n++
		}
	}
	return n
}
