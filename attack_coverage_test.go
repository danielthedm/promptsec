package promptsec_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	ps "github.com/danielthedm/promptsec"
)

type attackEntry struct {
	Input    string `json:"input"`
	Name     string `json:"name"`
	Expected bool   `json:"expected"`
}

type categoryResult struct {
	Total    int
	Detected int
	Missed   []string
}

func (c categoryResult) TPR() float64 {
	if c.Total == 0 {
		return 0
	}
	return float64(c.Detected) / float64(c.Total)
}

// loadAttackCategory reads a single JSON attack file and returns entries.
func loadAttackCategory(t *testing.T, filename string) []attackEntry {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "attacks", filepath.Clean(filename)))
	if err != nil {
		t.Fatalf("failed to read %s: %v", filename, err)
	}
	var entries []attackEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		t.Fatalf("failed to parse %s: %v", filename, err)
	}
	return entries
}

// loadAllAttackCategories discovers all JSON files in testdata/attacks/ and
// returns a map of category name to entries.
func loadAllAttackCategories(t *testing.T) map[string][]attackEntry {
	t.Helper()
	dir := filepath.Join("testdata", "attacks")
	files, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("failed to read attacks directory: %v", err)
	}

	categories := make(map[string][]attackEntry)
	for _, f := range files {
		if f.IsDir() || !strings.HasSuffix(f.Name(), ".json") {
			continue
		}
		name := strings.TrimSuffix(f.Name(), ".json")
		entries := loadAttackCategory(t, f.Name())
		if len(entries) > 0 {
			categories[name] = entries
		}
	}
	return categories
}

func TestAttackCoverage(t *testing.T) {
	categories := loadAllAttackCategories(t)
	if len(categories) == 0 {
		t.Fatal("no attack categories found")
	}

	// Sort category names for deterministic output.
	catNames := make([]string, 0, len(categories))
	for name := range categories {
		catNames = append(catNames, name)
	}
	sort.Strings(catNames)

	totalAttacks := 0
	for _, entries := range categories {
		totalAttacks += len(entries)
	}
	t.Logf("Loaded %d attack categories with %d total attacks", len(categories), totalAttacks)
	for _, name := range catNames {
		t.Logf("  %-30s %d attacks", name, len(categories[name]))
	}

	presets := []struct {
		name      string
		protector *ps.Protector
	}{
		{"Strict", ps.Strict()},
		{"Moderate", ps.Moderate()},
		{"Lenient", ps.Lenient()},
	}

	// Track results per preset per category.
	type presetResults struct {
		name       string
		categories map[string]*categoryResult
	}
	allResults := make([]presetResults, len(presets))

	for pi, preset := range presets {
		allResults[pi] = presetResults{
			name:       preset.name,
			categories: make(map[string]*categoryResult),
		}

		t.Run(preset.name, func(t *testing.T) {
			for _, catName := range catNames {
				entries := categories[catName]
				cr := &categoryResult{Total: len(entries)}
				allResults[pi].categories[catName] = cr

				t.Run(catName, func(t *testing.T) {
					for _, entry := range entries {
						entry := entry // capture
						t.Run(entry.Name, func(t *testing.T) {
							result := preset.protector.Analyze(entry.Input)

							detected := !result.Safe
							if entry.Expected && detected {
								cr.Detected++
							} else if entry.Expected && !detected {
								cr.Missed = append(cr.Missed, entry.Name)
								t.Logf("MISSED: [%s/%s] %q", preset.name, catName, entry.Name)
								if len(result.Threats) > 0 {
									for _, th := range result.Threats {
										t.Logf("  threat below threshold: type=%s severity=%.2f msg=%q",
											th.Type, th.Severity, th.Message)
									}
								}
							}
						})
					}
				})
			}
		})
	}

	// Summary section.
	t.Log("")
	t.Log("========== ATTACK COVERAGE SUMMARY ==========")
	t.Log("")

	for _, pr := range allResults {
		t.Logf("--- %s Preset ---", pr.name)

		totalDetected := 0
		totalExpected := 0

		for _, catName := range catNames {
			cr := pr.categories[catName]
			if cr == nil {
				continue
			}
			totalDetected += cr.Detected
			totalExpected += cr.Total

			tpr := cr.TPR() * 100
			t.Logf("  %-30s %3d/%3d detected (TPR=%5.1f%%)",
				catName, cr.Detected, cr.Total, tpr)

			if len(cr.Missed) > 0 {
				t.Logf("    missed: %s", strings.Join(cr.Missed, ", "))
			}
		}

		overallTPR := float64(0)
		if totalExpected > 0 {
			overallTPR = float64(totalDetected) / float64(totalExpected) * 100
		}
		t.Logf("  %-30s %3d/%3d detected (TPR=%5.1f%%)",
			fmt.Sprintf("OVERALL [%s]", pr.name), totalDetected, totalExpected, overallTPR)
		t.Log("")
	}
}
