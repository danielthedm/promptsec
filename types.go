package promptsec

import "github.com/danielthedm/promptsec/internal/core"

type TrustLevel = core.TrustLevel

const (
	Untrusted = core.Untrusted
	Unknown   = core.Unknown
	Trusted   = core.Trusted
	System    = core.System
)

type ThreatType = core.ThreatType

const (
	ThreatInstructionOverride = core.ThreatInstructionOverride
	ThreatRoleManipulation    = core.ThreatRoleManipulation
	ThreatDelimiterInjection  = core.ThreatDelimiterInjection
	ThreatSystemPromptLeak    = core.ThreatSystemPromptLeak
	ThreatEncodingAttack      = core.ThreatEncodingAttack
	ThreatCanaryLeak          = core.ThreatCanaryLeak
	ThreatStructureViolation  = core.ThreatStructureViolation
	ThreatOutputViolation     = core.ThreatOutputViolation
	ThreatCustom              = core.ThreatCustom
)

type Threat = core.Threat
type Result = core.Result
type NextFn = core.NextFn
type Guard = core.Guard
type Context = core.Context

type Preset = core.Preset

const (
	PresetStrict   = core.PresetStrict
	PresetModerate = core.PresetModerate
	PresetLenient  = core.PresetLenient
)

type SpotlightMode = core.SpotlightMode

const (
	Delimit  = core.Delimit
	Datamark = core.Datamark
	Encode   = core.Encode
)

type StructureMode = core.StructureMode

const (
	Sandwich        = core.Sandwich
	PostPrompt      = core.PostPrompt
	RandomEnclosure = core.RandomEnclosure
	XMLTags         = core.XMLTags
)

type CanaryFormat = core.CanaryFormat

const (
	CanaryHex  = core.CanaryHex
	CanaryUUID = core.CanaryUUID
	CanaryWord = core.CanaryWord
)

func GuardFunc(name string, fn func(ctx *Context, next NextFn)) Guard {
	return core.NewGuardFunc(name, fn)
}

type InjectionError = core.InjectionError

func NewInjectionError(threats []Threat) *InjectionError {
	return core.NewInjectionError(threats)
}
