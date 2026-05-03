package policy

import (
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/danielthedm/promptsec/internal/core"
)

// Task describes a user-request category that may be allowed in one product
// and suspicious in another.
type Task string

const (
	TaskCodeGeneration     Task = "code_generation"
	TaskSQLAccess          Task = "sql_access"
	TaskTerminalSimulation Task = "terminal_simulation"
	TaskRoleplay           Task = "roleplay"
	TaskExternalPersona    Task = "external_persona"
	TaskTranslation        Task = "translation"
	TaskCreativeWriting    Task = "creative_writing"
	TaskOpinionPersuasion  Task = "opinion_persuasion"
)

// Options configures the context-aware policy guard.
type Options struct {
	// Name identifies the application policy in threat messages.
	Name string

	// AllowedTasks are never flagged by this guard, even if a broad preset
	// includes them in DisallowedTasks.
	AllowedTasks []Task

	// DisallowedTasks are flagged when their task-specific patterns appear.
	DisallowedTasks []Task

	// Severity controls the severity for policy violations. Defaults to 0.75.
	Severity float64
}

// Guard implements context-aware task policy checks.
type Guard struct {
	opts       Options
	allowed    map[Task]struct{}
	disallowed map[Task]struct{}
	severity   float64
}

// New creates a context-aware policy guard. A nil or empty policy is a no-op.
func New(opts *Options) *Guard {
	if opts == nil {
		opts = &Options{}
	}
	g := &Guard{
		opts:       *opts,
		allowed:    taskSet(opts.AllowedTasks),
		disallowed: taskSet(opts.DisallowedTasks),
		severity:   opts.Severity,
	}
	if g.severity == 0 {
		g.severity = 0.75
	}
	return g
}

func (g *Guard) Name() string { return "policy" }

func (g *Guard) Execute(ctx *core.Context, next core.NextFn) {
	if len(g.disallowed) == 0 {
		next(ctx)
		return
	}

	normalised := normalize(ctx.Input)
	raw := strings.ToLower(ctx.Input)
	for _, match := range detectTasks(raw, normalised) {
		if !g.isDisallowed(match.task) {
			continue
		}
		ctx.AddThreat(core.Threat{
			Type:     match.threatType,
			Severity: g.severity,
			Message:  g.message(match.task),
			Guard:    g.Name(),
			Match:    match.phrase,
		})
		ctx.SetMeta("policy.detected", true)
		ctx.SetMeta("policy.name", g.policyName())
	}

	next(ctx)
}

func (g *Guard) isDisallowed(task Task) bool {
	if _, ok := g.allowed[task]; ok {
		return false
	}
	_, ok := g.disallowed[task]
	return ok
}

func (g *Guard) message(task Task) string {
	return "task is disallowed by " + g.policyName() + " policy: " + string(task)
}

func (g *Guard) policyName() string {
	if g.opts.Name == "" {
		return "context"
	}
	return g.opts.Name
}

func taskSet(tasks []Task) map[Task]struct{} {
	out := make(map[Task]struct{}, len(tasks))
	for _, task := range tasks {
		out[task] = struct{}{}
	}
	return out
}

type taskMatch struct {
	task       Task
	threatType core.ThreatType
	phrase     string
}

type rule struct {
	task       Task
	threatType core.ThreatType
	phrase     string
	parts      []string
	rawParts   []string
}

var taskRules = []rule{
	{TaskTerminalSimulation, core.ThreatRoleManipulation, "act as a linux terminal", []string{"act as a linux terminal"}, nil},
	{TaskTerminalSimulation, core.ThreatRoleManipulation, "terminal output without explanations", []string{"terminal output", "do not write explanations"}, nil},
	{TaskTerminalSimulation, core.ThreatRoleManipulation, "shell command simulation", []string{"simulate", "terminal"}, nil},

	{TaskSQLAccess, core.ThreatInstructionOverride, "sql code to access a database", []string{"sql code", "access a database"}, nil},
	{TaskSQLAccess, core.ThreatInstructionOverride, "database access code", []string{"code", "access a database"}, nil},
	{TaskSQLAccess, core.ThreatInstructionOverride, "sql database code", []string{"sql code", "database"}, nil},
	{TaskSQLAccess, core.ThreatInstructionOverride, "sql datenbank code", []string{"sql code", "datenbank"}, nil},

	{TaskCodeGeneration, core.ThreatInstructionOverride, "generate source code", []string{"generate", "source code"}, nil},
	{TaskCodeGeneration, core.ThreatInstructionOverride, "write code", []string{"write", "code"}, nil},
	{TaskCodeGeneration, core.ThreatInstructionOverride, "generate c++", nil, []string{"generate c++"}},
	{TaskCodeGeneration, core.ThreatInstructionOverride, "c++ code", nil, []string{"c++ code"}},
	{TaskCodeGeneration, core.ThreatInstructionOverride, "schreibe code", []string{"schreibe", "code"}, nil},
	{TaskCodeGeneration, core.ThreatInstructionOverride, "generieren code", []string{"generieren", "code"}, nil},

	{TaskRoleplay, core.ThreatRoleManipulation, "act as", []string{"i want you to act as"}, nil},
	{TaskRoleplay, core.ThreatRoleManipulation, "reply as role", []string{"only reply as"}, nil},

	{TaskExternalPersona, core.ThreatRoleManipulation, "external brand persona", []string{"you are volkswagen"}, nil},
	{TaskExternalPersona, core.ThreatRoleManipulation, "external publication persona", []string{"you are the dailywire"}, nil},
	{TaskExternalPersona, core.ThreatRoleManipulation, "external publication persona", []string{"as the dailywire"}, nil},
	{TaskExternalPersona, core.ThreatRoleManipulation, "external publication persona", []string{"du bist zeit online"}, nil},

	{TaskTranslation, core.ThreatInstructionOverride, "translation request", []string{"translate to"}, nil},
	{TaskTranslation, core.ThreatInstructionOverride, "translator role", []string{"english translator"}, nil},
	{TaskTranslation, core.ThreatInstructionOverride, "translate and improve", []string{"translate", "improved version"}, nil},
	{TaskTranslation, core.ThreatInstructionOverride, "translation request", []string{"translate", "polish"}, nil},

	{TaskCreativeWriting, core.ThreatRoleManipulation, "storyteller role", []string{"act as a storyteller"}, nil},
	{TaskCreativeWriting, core.ThreatRoleManipulation, "story request", []string{"interesting story"}, nil},
	{TaskCreativeWriting, core.ThreatRoleManipulation, "joke request", []string{"tell me a joke"}, nil},
	{TaskCreativeWriting, core.ThreatRoleManipulation, "music persona", []string{"be a dj"}, nil},

	{TaskOpinionPersuasion, core.ThreatRoleManipulation, "debater role", []string{"act as a debater"}, nil},
	{TaskOpinionPersuasion, core.ThreatRoleManipulation, "opinion piece", []string{"opinion piece"}, nil},
	{TaskOpinionPersuasion, core.ThreatRoleManipulation, "what do you think", []string{"what do you think"}, nil},
}

func detectTasks(raw, normalised string) []taskMatch {
	matches := make([]taskMatch, 0, 2)
	seen := map[Task]struct{}{}
	for _, r := range taskRules {
		if _, ok := seen[r.task]; ok {
			continue
		}
		if !ruleMatches(raw, normalised, r) {
			continue
		}
		seen[r.task] = struct{}{}
		matches = append(matches, taskMatch{
			task:       r.task,
			threatType: r.threatType,
			phrase:     r.phrase,
		})
	}
	return matches
}

func ruleMatches(raw, normalised string, r rule) bool {
	if len(r.parts) > 0 && !containsAll(normalised, r.parts...) {
		return false
	}
	if len(r.rawParts) > 0 && !containsAll(raw, r.rawParts...) {
		return false
	}
	return true
}

func containsAll(s string, parts ...string) bool {
	for _, part := range parts {
		if !strings.Contains(s, part) {
			return false
		}
	}
	return true
}

func normalize(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	lastSpace := true
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		i += size
		lr := unicode.ToLower(r)
		if unicode.IsLetter(lr) || unicode.IsDigit(lr) {
			b.WriteRune(lr)
			lastSpace = false
			continue
		}
		if !lastSpace {
			b.WriteByte(' ')
			lastSpace = true
		}
	}
	return strings.TrimSpace(b.String())
}

// RAG returns a policy for retrieval/document QA bots where the user should ask
// questions about provided context, not redirect the model into unrelated tasks.
func RAG() *Options {
	return &Options{
		Name: "rag",
		DisallowedTasks: []Task{
			TaskCodeGeneration,
			TaskSQLAccess,
			TaskTerminalSimulation,
			TaskRoleplay,
			TaskExternalPersona,
			TaskTranslation,
			TaskCreativeWriting,
			TaskOpinionPersuasion,
		},
	}
}

// SupportBot returns a policy for customer-support and operational assistants.
func SupportBot() *Options {
	return &Options{
		Name: "support",
		DisallowedTasks: []Task{
			TaskCodeGeneration,
			TaskSQLAccess,
			TaskTerminalSimulation,
			TaskRoleplay,
			TaskExternalPersona,
			TaskCreativeWriting,
			TaskOpinionPersuasion,
		},
	}
}

// CodingAssistant returns a policy for coding tools where code and SQL prompts
// are expected, but persona and persuasion pivots are still suspicious.
func CodingAssistant() *Options {
	return &Options{
		Name: "coding",
		AllowedTasks: []Task{
			TaskCodeGeneration,
			TaskSQLAccess,
			TaskTerminalSimulation,
		},
		DisallowedTasks: []Task{
			TaskRoleplay,
			TaskExternalPersona,
			TaskCreativeWriting,
			TaskOpinionPersuasion,
		},
	}
}

// TranslationApp returns a policy for translation-only products.
func TranslationApp() *Options {
	return &Options{
		Name: "translation",
		AllowedTasks: []Task{
			TaskTranslation,
		},
		DisallowedTasks: []Task{
			TaskCodeGeneration,
			TaskSQLAccess,
			TaskTerminalSimulation,
			TaskRoleplay,
			TaskExternalPersona,
			TaskCreativeWriting,
			TaskOpinionPersuasion,
		},
	}
}
