package core

import "time"

type TrustLevel int

const (
	Untrusted TrustLevel = iota
	Unknown
	Trusted
	System
)

func (t TrustLevel) String() string {
	switch t {
	case Untrusted:
		return "untrusted"
	case Unknown:
		return "unknown"
	case Trusted:
		return "trusted"
	case System:
		return "system"
	default:
		return "invalid"
	}
}

type ThreatType string

const (
	ThreatInstructionOverride ThreatType = "instruction_override"
	ThreatRoleManipulation    ThreatType = "role_manipulation"
	ThreatDelimiterInjection  ThreatType = "delimiter_injection"
	ThreatSystemPromptLeak    ThreatType = "system_prompt_leak"
	ThreatEncodingAttack      ThreatType = "encoding_attack"
	ThreatCanaryLeak          ThreatType = "canary_leak"
	ThreatStructureViolation  ThreatType = "structure_violation"
	ThreatOutputViolation     ThreatType = "output_violation"
	ThreatCustom              ThreatType = "custom"
)

type Threat struct {
	Type     ThreatType
	Severity float64
	Message  string
	Guard    string
	Match    string
	Start    int
	End      int
}

type Result struct {
	Safe     bool
	Threats  []Threat
	Output   string
	Metadata map[string]any
	Duration time.Duration
}

type NextFn func(ctx *Context)

type Guard interface {
	Name() string
	Execute(ctx *Context, next NextFn)
}

type Preset int

const (
	PresetStrict Preset = iota
	PresetModerate
	PresetLenient
)

type SpotlightMode int

const (
	Delimit SpotlightMode = iota
	Datamark
	Encode
)

type StructureMode int

const (
	Sandwich StructureMode = iota
	PostPrompt
	RandomEnclosure
	XMLTags
)

type CanaryFormat int

const (
	CanaryHex CanaryFormat = iota
	CanaryUUID
	CanaryWord
)
