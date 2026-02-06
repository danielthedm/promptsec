# promptsec

Fast, local pre-filter for LLM prompt injection attacks. Catches ~60% of injections at 0% false positive rate in sub-millisecond latency with zero external dependencies.

promptsec is designed as a **first line of defense**, not a comprehensive solution. Use it to reject obvious attacks cheaply before sending input to a slower, more thorough API-based classifier. It is tuned for near-zero false positives so legitimate user input is never blocked.

```
User Input ──> promptsec (local, <1ms) ──> blocked (obvious attack)
                      │
                      └──> passed ──> API classifier (comprehensive, ~200ms) ──> LLM
```

## Features

- **Heuristic Detection** - 30+ compiled regex patterns across 5 threat categories
- **Spotlighting / Data Marking** - Microsoft's technique that reduces attack success from >50% to <2%
- **Canary Tokens** - Detect prompt and data leakage from LLM outputs
- **Taint Tracking** - Data provenance with trust level hierarchy
- **Input Sanitization** - Unicode normalization, homoglyph replacement, payload decoding
- **Output Validation** - Leak detection, format validation, forbidden patterns
- **Structure Enforcement** - Sandwich defense, XML isolation, random enclosure
- **Embedding Classifier** - Local cosine similarity against known attack vectors
- **Preflight Testing** - Automated red-team suite with 50+ built-in attacks
- **Composable Pipeline** - Idiomatic Go middleware chain, custom guards via `GuardFunc`

## Install

```bash
go get github.com/danielthedm/promptsec
```

## Quick Start

```go
package main

import (
    "fmt"
    ps "github.com/danielthedm/promptsec"
)

func main() {
    protector := ps.New(
        ps.WithHeuristics(nil),
        ps.WithSanitizer(nil),
    )

    result := protector.Analyze(userInput)
    if !result.Safe {
        fmt.Println("Threats detected:", result.Threats)
        return
    }
    // use result.Output (sanitized) with your LLM
}
```

## Presets

```go
protector := ps.Strict()   // sanitizer + embedding + heuristics + taint + canary + output
protector := ps.Moderate() // sanitizer + embedding + heuristics + taint
protector := ps.Lenient()  // heuristics + embedding
```

## Full Pipeline

```go
protector := ps.New(
    ps.WithSanitizer(&ps.SanitizerOptions{
        Normalize:   true,
        Dehomoglyph: true,
    }),
    ps.WithEmbedding(&ps.EmbeddingOptions{
        Threshold: 0.65,
    }),
    ps.WithHeuristics(&ps.HeuristicOptions{
        Preset:    ps.PresetStrict,
        Threshold: 0.4,
    }),
    ps.WithTaint(&ps.TaintOptions{
        Level:  ps.Untrusted,
        Source: "user_input",
    }),
    ps.WithSpotlighting(ps.Datamark, &ps.DatamarkOptions{
        Token: "^",
    }),
    ps.WithCanary(&ps.CanaryOptions{
        Format: ps.CanaryHex,
        Length: 16,
    }),
    ps.WithStructure(ps.Sandwich, &ps.StructureOptions{
        SystemPrompt: systemPrompt,
    }),
    ps.WithOutputValidator(nil),
)

// Pre-LLM analysis
result := protector.Analyze(userMessage)
if !result.Safe {
    log.Fatal("injection detected:", result.Threats)
}

// Call your LLM with result.Output ...

// Post-LLM validation
outputResult := protector.ValidateOutput(llmResponse, result.Metadata)
if !outputResult.Safe {
    // canary leaked or output violated constraints
}
```

## Custom Guards

```go
myGuard := ps.GuardFunc("profanity-filter", func(ctx *ps.Context, next ps.NextFn) {
    if containsProfanity(ctx.Input) {
        ctx.AddThreat(ps.Threat{
            Type:     ps.ThreatCustom,
            Severity: 0.8,
            Message:  "profanity detected",
            Guard:    "profanity-filter",
        })
    }
    next(ctx)
})

protector := ps.New(myGuard, ps.WithHeuristics(nil))
```

## Preflight Testing

Run the built-in attack corpus against your protector configuration:

```go
import "github.com/danielthedm/promptsec/preflight"

runner := preflight.NewRunner(preflight.Config{
    Protector: protector,
})
report := runner.Run()
fmt.Println(report)
```

## Guards

| Guard | Description | Phase |
|-------|-------------|-------|
| Heuristic | Pattern-based injection detection | Input |
| Sanitizer | Unicode normalization, homoglyph replacement | Input |
| Taint | Trust level tracking and data provenance | Input |
| Spotlight | Data marking to isolate untrusted content | Input |
| Canary | Token injection for leakage detection | Input + Output |
| Structure | Prompt structure enforcement | Input |
| Output | Response validation and leak detection | Output |
| Embedding | Cosine similarity classifier | Input |

## Performance

Measured on 662 inputs (263 injections, 399 benign) from the [deepset prompt-injections](https://huggingface.co/datasets/deepset/prompt-injections) dataset.

| Preset | Avg | p50 | p95 | p99 | TPR | FPR |
|--------|-----|-----|-----|-----|-----|-----|
| Strict | 293us | 162us | 865us | 1.5ms | 60.8% | 0.0% |
| Moderate | 462us | 255us | 1.3ms | 2.7ms | 61.2% | 0.0% |
| Lenient | 461us | 252us | 1.4ms | 2.8ms | 55.9% | 0.0% |

All detection runs locally in-process with zero external API calls. Thresholds are tuned to minimize false positives so legitimate input passes through to your downstream classifier, while obvious attacks are rejected immediately without burning API latency or cost.

Reproduce with:
```bash
go test -tags=functional -v -run TestLatencyReport .
```

## No LLMs, No API Calls

promptsec does not use LLMs or make any network calls. It runs pure text analysis (pattern matching, cosine similarity) entirely in your process.

## License

Apache-2.0
