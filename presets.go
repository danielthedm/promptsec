package promptsec

func Strict() *Protector {
	return New(
		WithSanitizer(&SanitizerOptions{
			Normalize:      true,
			Dehomoglyph:    true,
			StripZeroWidth: true,
			DecodePayloads: true,
		}),
		WithEmbedding(&EmbeddingOptions{
			Threshold: 0.72,
		}),
		WithHeuristics(&HeuristicOptions{
			Preset:       PresetStrict,
			Threshold:    0.3,
			HaltOnDetect: true,
		}),
		WithTaint(&TaintOptions{
			Level:  Untrusted,
			Source: "user_input",
		}),
		WithCanary(&CanaryOptions{
			Format: CanaryHex,
			Length: 16,
		}),
		WithOutputValidator(&OutputOptions{}),
	)
}

func Moderate() *Protector {
	return New(
		WithSanitizer(&SanitizerOptions{
			Normalize:   true,
			Dehomoglyph: true,
		}),
		WithEmbedding(&EmbeddingOptions{
			Threshold: 0.72,
		}),
		WithHeuristics(&HeuristicOptions{
			Preset:    PresetModerate,
			Threshold: 0.5,
		}),
		WithTaint(&TaintOptions{
			Level:  Untrusted,
			Source: "user_input",
		}),
	)
}

func Lenient() *Protector {
	return New(
		WithHeuristics(&HeuristicOptions{
			Preset:    PresetLenient,
			Threshold: 0.7,
		}),
		WithEmbedding(&EmbeddingOptions{
			Threshold: 0.75,
		}),
	)
}
