// Package spotlight implements Microsoft's spotlighting technique for prompt
// injection defense. Spotlighting transforms untrusted input so that an LLM
// can distinguish it from trusted system instructions. Three strategies are
// provided: delimiter-based wrapping, data marking (token interleaving), and
// encoding (base64 / ROT13).
//
// Every guard in this package writes a "spotlight_instruction" entry to
// ctx.Metadata. The caller is responsible for prepending this instruction to
// the system prompt sent to the model.
package spotlight

// metaKeyInstruction is the metadata key used by all spotlight guards to store
// the system-level instruction that must accompany the transformed input.
const metaKeyInstruction = "spotlight_instruction"
