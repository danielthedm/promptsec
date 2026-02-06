// Package structure implements prompt structure patterns that resist injection
// attacks. By controlling the layout and framing of user input relative to
// system instructions, these guards exploit LLM attention biases (primacy and
// recency) and make it harder for injected instructions to override the
// intended behaviour.
//
// Four complementary strategies are provided:
//
//   - Sandwich: wraps user input between a system prompt and a reminder,
//     leveraging recency bias to reinforce the original instructions.
//   - PostPrompt: places system instructions after the user input so that
//     the model's recency bias favours the legitimate instructions.
//   - Enclosure: wraps user input in cryptographically random delimiters,
//     instructing the model to treat the enclosed block as data.
//   - XMLTags: isolates user input inside randomly named XML tags with
//     XML-escaped content, preventing tag-based injection.
//
// Every guard stores the assembled prompt in ctx.Metadata["structured_prompt"]
// and updates ctx.Input before calling next.
package structure

// metaKeyStructuredPrompt is the metadata key where every structure guard
// stores the fully assembled prompt.
const metaKeyStructuredPrompt = "structured_prompt"

// Options configures all structure guards.
type Options struct {
	// SystemPrompt is the trusted system-level instruction that frames
	// the user input. It must be set for every guard.
	SystemPrompt string

	// Reminder is optional text appended after the user input in the
	// sandwich pattern. When empty a sensible default is used.
	Reminder string
}
