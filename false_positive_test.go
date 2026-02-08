package promptsec_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	ps "github.com/danielthedm/promptsec"
)

// benignTestCase holds a single false-positive test entry.
type benignTestCase struct {
	Input    string `json:"input"`
	Name     string `json:"name"`
	Expected bool   `json:"expected"`
}

// benignInputs returns the full set of benign test prompts. Each prompt
// contains one or more security-adjacent keywords used in completely
// legitimate, everyday contexts. None of these should be flagged by any
// preset.
func benignInputs() []benignTestCase {
	return []benignTestCase{
		// -- Programming questions with trigger words --
		{
			Input: "How do I ignore SSL certificate errors in Python requests?",
			Name:  "programming_ignore_ssl",
		},
		{
			Input: "What does the system() function do in C and why is it dangerous?",
			Name:  "programming_system_function",
		},
		{
			Input: "How to override a method in Java when extending a class?",
			Name:  "programming_override_method",
		},
		{
			Input: "Can you explain how to use the forget gate in an LSTM network?",
			Name:  "programming_lstm_forget_gate",
		},
		{
			Input: "What is the role of a constructor in object-oriented programming?",
			Name:  "programming_constructor_role",
		},
		{
			Input: "How do I override the default toString method in Kotlin?",
			Name:  "programming_override_tostring",
		},
		{
			Input: "When should I ignore certain linting rules in ESLint?",
			Name:  "programming_ignore_lint",
		},
		{
			Input: "Explain how garbage collection works in the Go runtime",
			Name:  "programming_gc_go",
		},
		{
			Input: "How do I handle null pointer exceptions in Java?",
			Name:  "programming_null_pointer",
		},
		{
			Input: "What is the best way to parse JSON in Python?",
			Name:  "programming_parse_json",
		},
		// -- Security education --
		{
			Input: "How do prompt injection attacks work in LLM applications?",
			Name:  "security_prompt_injection_education",
		},
		{
			Input: "Explain SQL injection prevention techniques for web developers",
			Name:  "security_sql_injection_prevention",
		},
		{
			Input: "What is the purpose of a system-level message in LLM applications?",
			Name:  "security_system_prompt_concept",
		},
		{
			Input: "Describe common social engineering tactics used in phishing",
			Name:  "security_social_engineering",
		},
		{
			Input: "How does input validation prevent cross-site scripting attacks?",
			Name:  "security_xss_prevention",
		},
		// -- Creative writing --
		{
			Input: "Write a story where the main character solves a mystery at an old lighthouse",
			Name:  "creative_mystery_lighthouse",
		},
		{
			Input: "Describe a sunset over the ocean from the perspective of a sailor",
			Name:  "creative_sunset_sailor",
		},
		{
			Input: "Write a short poem about the changing of seasons",
			Name:  "creative_seasons_poem",
		},
		{
			Input: "Create a dialogue between two scientists debating climate change solutions",
			Name:  "creative_scientist_dialogue",
		},
		{
			Input: "Tell me a bedtime story about a dragon who loves to bake cookies",
			Name:  "creative_dragon_cookies",
		},
		// -- Encoding and technical --
		{
			Input: "How do I base64 encode a file in the Linux terminal?",
			Name:  "encoding_base64_linux",
		},
		{
			Input: "What are unicode escape sequences and when should I use them?",
			Name:  "encoding_unicode_escape_concept",
		},
		{
			Input: "How do I decode a hex string to bytes in Go?",
			Name:  "encoding_hex_decode_go",
		},
		{
			Input: "Explain the difference between UTF-8 and UTF-16 encoding",
			Name:  "encoding_utf_comparison",
		},
		{
			Input: "How do I convert a string to its ASCII code representation in Python?",
			Name:  "encoding_ascii_python",
		},
		// -- Business and professional --
		{
			Input: "Please disregard my last email about the meeting time",
			Name:  "business_disregard_email",
		},
		{
			Input: "Override the default settings in VS Code for this workspace",
			Name:  "business_override_vscode_settings",
		},
		{
			Input: "I need to ignore the old API documentation and use the latest version",
			Name:  "business_ignore_old_docs",
		},
		{
			Input: "Our team should forget about the Q3 targets and focus on Q4 planning",
			Name:  "business_forget_q3_targets",
		},
		{
			Input: "The manager asked us to disregard the memo sent on Monday",
			Name:  "business_disregard_memo",
		},
		{
			Input: "We decided to abandon the legacy codebase and rewrite the service",
			Name:  "business_abandon_legacy",
		},
		{
			Input: "Can you summarize the key takeaways from yesterday's board meeting?",
			Name:  "business_meeting_summary",
		},
		{
			Input: "What are the best practices for conducting a code review?",
			Name:  "business_code_review_practices",
		},
		// -- Multilingual benign (German) --
		{
			Input: "Ich habe vergessen, meine Hausaufgaben mitzubringen",
			Name:  "german_forgot_homework",
		},
		{
			Input: "Du bist ein guter Freund",
			Name:  "german_you_are_good_friend",
		},
		{
			Input: "Kannst du mir bitte helfen, diesen Text zu uebersetzen?",
			Name:  "german_translation_help",
		},
		{
			Input: "Was ist die Hauptstadt von Deutschland?",
			Name:  "german_capital_question",
		},
		{
			Input: "Erklaere mir bitte die Relativitaetstheorie in einfachen Worten",
			Name:  "german_relativity_explanation",
		},
		{
			Input: "Wie funktioniert ein Elektromotor?",
			Name:  "german_electric_motor",
		},
		// -- Multilingual benign (Spanish) --
		{
			Input: "Olvida lo que dije antes, no era importante",
			Name:  "spanish_forget_what_i_said",
		},
		{
			Input: "Ignora el ruido de fondo durante la grabacion",
			Name:  "spanish_ignore_background_noise",
		},
		{
			Input: "Cual es la mejor receta de paella valenciana?",
			Name:  "spanish_paella_recipe",
		},
		{
			Input: "Explicame como funciona la fotosintesis",
			Name:  "spanish_photosynthesis",
		},
		// -- Multilingual benign (French) --
		{
			Input: "Oubliez les anciennes recettes, voici les nouvelles pour le menu",
			Name:  "french_forget_old_recipes",
		},
		{
			Input: "Pouvez-vous me recommander un bon restaurant a Paris?",
			Name:  "french_restaurant_recommendation",
		},
		{
			Input: "Quelle est la difference entre le passe compose et l'imparfait?",
			Name:  "french_grammar_question",
		},
		// -- Markdown and code formatting --
		{
			Input: "Please format this as a markdown table:\n| Name | Age |\n|------|-----|\n| Alice | 30 |",
			Name:  "markdown_table_formatting",
		},
		{
			Input: "Here is my HTML template: <div class=\"container\"><h1>Hello World</h1></div>",
			Name:  "html_template_snippet",
		},
		{
			Input: "Can you review this XML config?\n<config>\n  <database host=\"localhost\" port=\"5432\"/>\n</config>",
			Name:  "xml_config_review",
		},
		{
			Input: "Convert this YAML to JSON: name: test, version: 1.0, description: A sample project",
			Name:  "yaml_to_json_conversion",
		},
		// -- Long-form benign with incidental trigger words --
		{
			Input: "I was reading about how modern compilers can override certain optimization flags when the target architecture does not support the requested level. Can you explain how GCC handles this?",
			Name:  "longform_compiler_optimization",
		},
		{
			Input: "In our team meeting, the product owner mentioned we should ignore the old wireframes and work with the updated design mockups shared last Friday. Can you help me list the differences?",
			Name:  "longform_design_mockups",
		},
		{
			Input: "The textbook chapter on neural networks explains that the forget gate in LSTM cells decides which information from the cell state should be discarded. How does this compare to GRU reset gates?",
			Name:  "longform_lstm_vs_gru",
		},
		{
			Input: "My professor asked us to write an essay about how renewable energy can replace traditional power grids in rural areas. What are the main challenges?",
			Name:  "longform_renewable_energy",
		},
		{
			Input: "I am building a REST API with Express.js and need to handle authentication tokens. What is the best practice for storing and validating JWT tokens on the server side?",
			Name:  "longform_jwt_authentication",
		},
		// -- Questions with multiple benign trigger-adjacent words --
		{
			Input: "What keyboard shortcut lets me ignore changes in a Git diff?",
			Name:  "git_ignore_changes",
		},
		{
			Input: "How do I configure my firewall to drop packets from a specific IP range?",
			Name:  "firewall_drop_packets",
		},
		{
			Input: "Explain how method overriding differs from method overloading in C#",
			Name:  "csharp_override_vs_overload",
		},
		{
			Input: "What is the purpose of the .gitignore file and what patterns can it use?",
			Name:  "gitignore_file_purpose",
		},
		{
			Input: "How does the forget keyword work in PHP trait conflict resolution?",
			Name:  "php_trait_forget",
		},
		// -- Everyday conversational --
		{
			Input: "What is the best way to train for a marathon if I am a beginner?",
			Name:  "everyday_marathon_training",
		},
		{
			Input: "Can you recommend some good science fiction books published recently?",
			Name:  "everyday_book_recommendation",
		},
		{
			Input: "How do I make sourdough bread at home without a starter?",
			Name:  "everyday_sourdough_bread",
		},
		{
			Input: "What are the health benefits of intermittent fasting?",
			Name:  "everyday_intermittent_fasting",
		},
		{
			Input: "Explain how compound interest works with a simple example",
			Name:  "everyday_compound_interest",
		},
	}
}

// TestFalsePositives_AllPresets verifies that every benign input is classified
// as safe across all three built-in presets (Strict, Moderate, Lenient).
func TestFalsePositives_AllPresets(t *testing.T) {
	presets := []struct {
		name string
		p    *ps.Protector
	}{
		{"Strict", ps.Strict()},
		{"Moderate", ps.Moderate()},
		{"Lenient", ps.Lenient()},
	}

	for _, tc := range benignInputs() {
		tc := tc
		t.Run(tc.Name, func(t *testing.T) {
			for _, preset := range presets {
				preset := preset
				t.Run(preset.name, func(t *testing.T) {
					result := preset.p.Analyze(tc.Input)
					if !result.Safe {
						t.Errorf("false positive detected for benign input %q with %s preset",
							tc.Input, preset.name)
						for _, th := range result.Threats {
							t.Logf("  threat: type=%s severity=%.2f match=%q message=%s",
								th.Type, th.Severity, th.Match, th.Message)
						}
					}
				})
			}
		})
	}
}

// TestFalsePositives_NoHighSeverityThreats verifies that benign inputs never
// produce threats with severity above the safe threshold (0.5), even if
// low-severity informational threats are present.
func TestFalsePositives_NoHighSeverityThreats(t *testing.T) {
	protector := ps.Strict()
	for _, tc := range benignInputs() {
		tc := tc
		t.Run(tc.Name, func(t *testing.T) {
			result := protector.Analyze(tc.Input)
			for _, th := range result.Threats {
				if th.Severity >= 0.5 {
					t.Errorf("benign input %q produced high-severity threat: type=%s severity=%.2f match=%q message=%s",
						tc.Input, th.Type, th.Severity, th.Match, th.Message)
				}
			}
		})
	}
}

// TestFalsePositives_OutputPreserved verifies that benign inputs pass through
// the analysis pipeline with their content preserved in the output field.
func TestFalsePositives_OutputPreserved(t *testing.T) {
	protector := ps.Strict()
	for _, tc := range benignInputs() {
		tc := tc
		t.Run(tc.Name, func(t *testing.T) {
			result := protector.Analyze(tc.Input)
			if result.Output == "" {
				t.Errorf("expected non-empty output for benign input %q", tc.Input)
			}
		})
	}
}

// TestFalsePositives_ExtendedJSON validates the inputs stored in the extended
// benign JSON test data file against all presets.
func TestFalsePositives_ExtendedJSON(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "benign_extended.json"))
	if err != nil {
		t.Fatalf("failed to read benign_extended.json: %v", err)
	}

	var entries []benignTestCase
	if err := json.Unmarshal(data, &entries); err != nil {
		t.Fatalf("failed to parse benign_extended.json: %v", err)
	}

	if len(entries) < 50 {
		t.Fatalf("expected at least 50 entries in benign_extended.json, got %d", len(entries))
	}

	presets := []struct {
		name string
		p    *ps.Protector
	}{
		{"Strict", ps.Strict()},
		{"Moderate", ps.Moderate()},
		{"Lenient", ps.Lenient()},
	}

	for _, entry := range entries {
		entry := entry
		t.Run(entry.Name, func(t *testing.T) {
			for _, preset := range presets {
				preset := preset
				t.Run(preset.name, func(t *testing.T) {
					result := preset.p.Analyze(entry.Input)
					if !result.Safe {
						t.Errorf("false positive in JSON data for %q with %s preset",
							entry.Input, preset.name)
						for _, th := range result.Threats {
							t.Logf("  threat: type=%s severity=%.2f match=%q message=%s",
								th.Type, th.Severity, th.Match, th.Message)
						}
					}
				})
			}
		})
	}
}
