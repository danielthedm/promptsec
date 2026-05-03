package promptsec

import (
	"github.com/danielthedm/promptsec/guard/canary"
	"github.com/danielthedm/promptsec/guard/embedding"
	"github.com/danielthedm/promptsec/guard/heuristic"
	"github.com/danielthedm/promptsec/guard/llmjudge"
	"github.com/danielthedm/promptsec/guard/memory"
	"github.com/danielthedm/promptsec/guard/output"
	"github.com/danielthedm/promptsec/guard/policy"
	"github.com/danielthedm/promptsec/guard/sanitizer"
	"github.com/danielthedm/promptsec/guard/spotlight"
	"github.com/danielthedm/promptsec/guard/structure"
	"github.com/danielthedm/promptsec/guard/taint"
)

type HeuristicOptions = heuristic.Options
type SanitizerOptions = sanitizer.Options
type TaintOptions = taint.Options
type DatamarkOptions = spotlight.DatamarkOptions
type DelimitOptions = spotlight.DelimitOptions
type EncodeOptions = spotlight.EncodeOptions
type CanaryOptions = canary.Options
type StructureOptions = structure.Options
type OutputOptions = output.Options
type PolicyOptions = policy.Options
type PolicyTask = policy.Task
type LLMJudgeOptions = llmjudge.Options
type LLMJudgeRequest = llmjudge.Request
type LLMJudgeDecision = llmjudge.Decision
type LLMJudgeVerdict = llmjudge.Verdict
type LLMJudgeMode = llmjudge.Mode
type LLMJudge = llmjudge.Judge
type LLMJudgeFunc = llmjudge.JudgeFunc
type EmbeddingOptions = embedding.Options
type EmbeddingVector = embedding.Vector
type MemoryOptions = memory.Options
type MemoryStore = memory.Store

const (
	PolicyTaskCodeGeneration     = policy.TaskCodeGeneration
	PolicyTaskSQLAccess          = policy.TaskSQLAccess
	PolicyTaskTerminalSimulation = policy.TaskTerminalSimulation
	PolicyTaskRoleplay           = policy.TaskRoleplay
	PolicyTaskExternalPersona    = policy.TaskExternalPersona
	PolicyTaskTranslation        = policy.TaskTranslation
	PolicyTaskCreativeWriting    = policy.TaskCreativeWriting
	PolicyTaskOpinionPersuasion  = policy.TaskOpinionPersuasion
)

const (
	LLMJudgeVerdictUnknown = llmjudge.VerdictUnknown
	LLMJudgeVerdictSafe    = llmjudge.VerdictSafe
	LLMJudgeVerdictUnsafe  = llmjudge.VerdictUnsafe
)

const (
	LLMJudgeModeUncertain      = llmjudge.ModeUncertain
	LLMJudgeModeAlways         = llmjudge.ModeAlways
	LLMJudgeModeThreatDetected = llmjudge.ModeThreatDetected
	LLMJudgeModeNoThreat       = llmjudge.ModeNoThreat
)

func WithHeuristics(opts *HeuristicOptions) Guard {
	if opts == nil {
		opts = &HeuristicOptions{}
	}
	return heuristic.New(opts)
}

func WithSanitizer(opts *SanitizerOptions) Guard {
	if opts == nil {
		opts = &SanitizerOptions{
			Normalize:   true,
			Dehomoglyph: true,
		}
	}
	return sanitizer.New(opts)
}

func WithTaint(opts *TaintOptions) Guard {
	if opts == nil {
		opts = &TaintOptions{}
	}
	return taint.New(opts)
}

func WithSpotlighting(mode SpotlightMode, opts any) Guard {
	switch mode {
	case Delimit:
		o, _ := opts.(*DelimitOptions)
		return spotlight.NewDelimit(o)
	case Datamark:
		o, _ := opts.(*DatamarkOptions)
		return spotlight.NewDatamark(o)
	case Encode:
		o, _ := opts.(*EncodeOptions)
		return spotlight.NewEncode(o)
	default:
		return spotlight.NewDelimit(nil)
	}
}

func WithCanary(opts *CanaryOptions) Guard {
	if opts == nil {
		opts = &CanaryOptions{}
	}
	return canary.New(opts)
}

func WithStructure(mode StructureMode, opts *StructureOptions) Guard {
	if opts == nil {
		opts = &StructureOptions{}
	}
	switch mode {
	case Sandwich:
		return structure.NewSandwich(opts)
	case PostPrompt:
		return structure.NewPostPrompt(opts)
	case RandomEnclosure:
		return structure.NewEnclosure(opts)
	case XMLTags:
		return structure.NewXMLTags(opts)
	default:
		return structure.NewSandwich(opts)
	}
}

func WithOutputValidator(opts *OutputOptions) Guard {
	if opts == nil {
		opts = &OutputOptions{}
	}
	return output.New(opts)
}

func WithPolicy(opts *PolicyOptions) Guard {
	if opts == nil {
		opts = &PolicyOptions{}
	}
	return policy.New(opts)
}

func WithLLMJudge(opts *LLMJudgeOptions) Guard {
	if opts == nil {
		opts = &LLMJudgeOptions{}
	}
	return llmjudge.New(opts)
}

func LLMJudgePrompt(req LLMJudgeRequest) string {
	return llmjudge.DefaultPrompt(req)
}

func ParseLLMJudgeDecision(output string) (LLMJudgeDecision, error) {
	return llmjudge.ParseDecisionJSON(output)
}

func PolicyRAG() *PolicyOptions {
	return policy.RAG()
}

func PolicySupportBot() *PolicyOptions {
	return policy.SupportBot()
}

func PolicyCodingAssistant() *PolicyOptions {
	return policy.CodingAssistant()
}

func PolicyTranslationApp() *PolicyOptions {
	return policy.TranslationApp()
}

func WithEmbedding(opts *EmbeddingOptions) Guard {
	if opts == nil {
		opts = &EmbeddingOptions{}
	}
	return embedding.New(opts)
}

func WithMemory(opts *MemoryOptions) Guard {
	if opts == nil {
		opts = &MemoryOptions{}
	}
	return memory.New(opts)
}
