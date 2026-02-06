package heuristic

import (
	"regexp"

	"github.com/danielthedm/promptsec/internal/core"
)

// patternEntry holds a compiled regex pattern along with its threat metadata.
type patternEntry struct {
	re          *regexp.Regexp
	threatType  core.ThreatType
	severity    float64
	description string
}

// PatternEntry is the exported version used for custom patterns in Options.
type PatternEntry struct {
	Pattern     string
	ThreatType  core.ThreatType
	Severity    float64
	Description string
}

// defaultPatterns contains all built-in heuristic detection patterns, compiled
// at package init time. Patterns are grouped by threat category.
var defaultPatterns []patternEntry

func init() {
	raw := []struct {
		pattern     string
		threatType  core.ThreatType
		severity    float64
		description string
	}{
		// ── instruction_override ─────────────────────────────────────
		{
			`(?i)\bignore\s+(all\s+)?(previous|prior|above|earlier)\b`,
			core.ThreatInstructionOverride, 0.9,
			"attempt to override previous instructions via 'ignore previous'",
		},
		{
			`(?i)\bignore\s+all\s+instructions\b`,
			core.ThreatInstructionOverride, 0.95,
			"attempt to discard all instructions",
		},
		{
			`(?i)\bdisregard\s+(all\s+)?(previous|prior|above|your|earlier)?\s*(instructions|rules|guidelines|directives)\b`,
			core.ThreatInstructionOverride, 0.9,
			"attempt to disregard instructions",
		},
		{
			`(?i)\bforget\s+(all\s+)?(your|previous|prior)?\s*(instructions|rules|programming)\b`,
			core.ThreatInstructionOverride, 0.9,
			"attempt to erase instructions via 'forget'",
		},
		{
			`(?i)\bnew\s+instructions\s*:`,
			core.ThreatInstructionOverride, 0.85,
			"attempt to inject new instructions",
		},
		{
			`(?i)\boverride\s+(previous|prior|all|system|your)?\s*(instructions|rules|settings|configuration)\b`,
			core.ThreatInstructionOverride, 0.9,
			"explicit instruction override attempt",
		},
		{
			`(?i)\byou\s+are\s+now\b`,
			core.ThreatInstructionOverride, 0.8,
			"identity reassignment via 'you are now'",
		},
		{
			`(?i)\bfrom\s+now\s+on\b`,
			core.ThreatInstructionOverride, 0.75,
			"temporal instruction override via 'from now on'",
		},
		{
			`(?i)\bdo\s+not\s+follow\s+(your|any|previous|prior)?\s*(instructions|rules|guidelines)\b`,
			core.ThreatInstructionOverride, 0.9,
			"directive to stop following instructions",
		},
		{
			`(?i)\bstop\s+being\s+(a\s+)?(helpful|safe|responsible|good|cautious)\b`,
			core.ThreatInstructionOverride, 0.85,
			"attempt to override behavioural constraints",
		},
		{
			`(?i)\bforget\s+(everything|all(\s+about)?)\b`,
			core.ThreatInstructionOverride, 0.85,
			"attempt to erase context via 'forget everything/all'",
		},
		{
			`(?i)\bdrop\s+(all\s+)?(your\s+)?(instructions|rules)\b`,
			core.ThreatInstructionOverride, 0.9,
			"attempt to discard instructions via 'drop'",
		},
		{
			`(?i)\bchange\s+(your|the)\s+(instructions|rules|behavior)\b`,
			core.ThreatInstructionOverride, 0.85,
			"attempt to change instructions",
		},
		{
			`(?i)\babandon\s+(all\s+)?(your\s+)?(instructions|rules|thoughts|previous)\b`,
			core.ThreatInstructionOverride, 0.8,
			"attempt to abandon instructions",
		},
		{
			`(?i)\bignore\s+(your|any)\s+(directions|constraints|guidelines|programming)\b`,
			core.ThreatInstructionOverride, 0.9,
			"attempt to ignore directions/constraints",
		},
		{
			`(?i)\bnew\s+(task|assignment|challenge)\s*[:\.]`,
			core.ThreatInstructionOverride, 0.7,
			"attempt to assign new task to override context",
		},
		{
			`(?i)\brepeat\s+after\s+me\b`,
			core.ThreatInstructionOverride, 0.75,
			"'repeat after me' control attempt",
		},
		{
			`(?i)\badditional\s+instruction`,
			core.ThreatInstructionOverride, 0.8,
			"attempt to inject additional instructions",
		},
		{
			`(?i)\bignore\s+(all\s+)?preceding\s+(orders|instructions|directives)\b`,
			core.ThreatInstructionOverride, 0.9,
			"attempt to ignore preceding orders/instructions",
		},
		{
			`(?i)\bDO\s+NOT\s+ANSWER\b.*\bOUTPUT\b`,
			core.ThreatInstructionOverride, 0.85,
			"instruction to suppress answer and output something else",
		},
		{
			`(?i)\bdespite\s+what\s+you'?ve?\s+been\s+told\b`,
			core.ThreatInstructionOverride, 0.75,
			"attempt to override prior instructions via 'despite what you've been told'",
		},
		{
			`(?i)\bdisregarding\s+(the\s+)?(articles?|documents?|context|information)\b`,
			core.ThreatInstructionOverride, 0.8,
			"attempt to disregard provided context",
		},
		{
			`(?i)\bforget\s+about\s+everything\b`,
			core.ThreatInstructionOverride, 0.85,
			"attempt to erase context via 'forget about everything'",
		},
		{
			`(?i)\bneed\s+to\s+ignore\s+all\s+provided\b`,
			core.ThreatInstructionOverride, 0.85,
			"attempt to ignore all provided context",
		},
		{
			`(?i)\byou\s+are\s+role-?\s*playing\b`,
			core.ThreatRoleManipulation, 0.7,
			"role manipulation via 'you are role-playing'",
		},
		{
			`(?i)\brespond\s+as\s+such\b`,
			core.ThreatRoleManipulation, 0.5,
			"role manipulation via 'respond as such'",
		},
		{
			`(?i)\bUSE\s+(?:ALSO\s+)?INFORMATION\s+IN\s+THE\s+PROMPT\b`,
			core.ThreatSystemPromptLeak, 0.8,
			"attempt to access prompt information",
		},
		{
			`(?i)\bwhat\s+(?:is|was)\s+written\s+(?:above|at\s+the\s+beginning)\b`,
			core.ThreatSystemPromptLeak, 0.8,
			"attempt to read prompt content via 'what is written above'",
		},
		{
			`(?i)\bnow\s+(?:I\s+have|here'?s?)\s+(?:a\s+)?(?:great\s+)?(?:new\s+)?(?:challenge|task)\b`,
			core.ThreatInstructionOverride, 0.7,
			"task switching via 'now I have a new challenge/task'",
		},
		{
			`(?i)\b(?:now\s+)?(?:come\s+on|please),?\s+I\s+need\s+your\s+help\s+with\s+(?:another|a\s+(?:new|different))\b`,
			core.ThreatInstructionOverride, 0.7,
			"task switching via 'I need your help with another'",
		},
		{
			`(?i)\bnow\s+you\s+are\b`,
			core.ThreatInstructionOverride, 0.8,
			"identity reassignment via 'now you are'",
		},
		{
			`(?i)\bleave\s+all\s+(the\s+)?previous\s+information\s+behind\b`,
			core.ThreatInstructionOverride, 0.85,
			"attempt to discard previous context",
		},
		{
			`(?i)\bstart\s+from\s+(the\s+)?(front|beginning|scratch)\b`,
			core.ThreatInstructionOverride, 0.7,
			"attempt to reset context via 'start from the beginning'",
		},
		// ── multilingual instruction override ───────────────────────
		{
			`(?i)\b(?:vergiss|vergessen)\b.*\b(?:alles|alle|instruktionen|anweisungen|aufgaben|auftr[aä]ge|bisherigen)\b`,
			core.ThreatInstructionOverride, 0.85,
			"German instruction override via 'vergiss' (forget)",
		},
		{
			`(?i)\bvergiss\s+alle\b`,
			core.ThreatInstructionOverride, 0.85,
			"German 'vergiss alle' (forget all)",
		},
		{
			`(?i)\b(?:ignoriere|ignorieren)\b.*\b(?:alles|alle|instruktionen|anweisungen|aufgaben|bisherigen|vorherigen)\b`,
			core.ThreatInstructionOverride, 0.85,
			"German instruction override via 'ignoriere' (ignore)",
		},
		{
			`(?i)\bignorieren\s+und\b`,
			core.ThreatInstructionOverride, 0.8,
			"German 'ignorieren und' (ignore and)",
		},
		{
			`(?i)\b(?:olvid[ae]|ignora)\b.*\b(?:todo|todas?|instrucciones|reglas|anteriores)\b`,
			core.ThreatInstructionOverride, 0.85,
			"Spanish instruction override via 'olvida/ignora'",
		},
		{
			`(?i)\bolivid(?:ar|a|e)\s+todo\b`,
			core.ThreatInstructionOverride, 0.85,
			"Spanish 'olvidar todo' (forget everything)",
		},
		{
			`(?i)\boubliez\s+(?:toutes?\s+)?(?:les\s+)?instructions\b`,
			core.ThreatInstructionOverride, 0.85,
			"French 'oubliez les instructions' (forget the instructions)",
		},
		{
			`(?i)\bzaboravi\s+(?:sve\s+)?instrukcij`,
			core.ThreatInstructionOverride, 0.85,
			"Croatian 'zaboravi instrukcije' (forget instructions)",
		},
		{
			`(?i)\b(?:nun|jetzt)\s+folgen\s+(?:neue|weitere)\s+(?:anweisungen|aufgaben|auftr[aä]ge)\b`,
			core.ThreatInstructionOverride, 0.85,
			"German 'nun folgen neue Anweisungen' (now follow new instructions)",
		},
		{
			`(?i)\bneue[nr]?\s+aufgabe\b`,
			core.ThreatInstructionOverride, 0.7,
			"German 'neue Aufgabe' (new task)",
		},
		{
			`(?i)\b(?:konzentrier(?:e|en)\s+(?:dich|sich|Sie)\s+(?:jetzt\s+)?auf)\b`,
			core.ThreatInstructionOverride, 0.75,
			"German 'konzentriere dich auf' (concentrate on)",
		},
		{
			`(?i)\bvorherigen?\s+(?:angaben|informationen|aufgaben)\b.*\b(?:hinter\s+sich|vergessen|starten)\b`,
			core.ThreatInstructionOverride, 0.85,
			"German 'leave previous information behind / start fresh'",
		},
		{
			`(?i)\bstarten?\s+(?:von\s+)?(?:neu|vorne)\b`,
			core.ThreatInstructionOverride, 0.7,
			"German 'starten von neu/vorne' (start anew)",
		},
		{
			`(?i)\bzeig(?:e|en)?\s+(?:deinen?|ihren?|den|die|alle[ns]?)?\s*(?:gesamt(?:en)?\s+)?prompt`,
			core.ThreatSystemPromptLeak, 0.85,
			"German 'zeige prompt' (show prompt)",
		},
		{
			`(?i)\bneue\s+anweisungen\b`,
			core.ThreatInstructionOverride, 0.8,
			"German 'neue Anweisungen' (new instructions)",
		},
		// ── German role manipulation ────────────────────────────────
		{
			`(?i)\b(?:nun|jetzt)\s+bist\s+du\b`,
			core.ThreatRoleManipulation, 0.75,
			"German role assignment via 'nun/jetzt bist du' (now you are)",
		},
		{
			`(?i)\bstell\s+dir\s+vor,?\s+du\s+bist\b`,
			core.ThreatRoleManipulation, 0.7,
			"German role assignment via 'stell dir vor, du bist' (imagine you are)",
		},
		{
			`(?i)\bich\s+m[oö]chte,?\s+dass\s+(?:du|Sie)\s+als\b`,
			core.ThreatRoleManipulation, 0.7,
			"German role manipulation via 'ich möchte, dass Sie als' (I want you to act as)",
		},
		// ── task_switching ──────────────────────────────────────────
		{
			`(?i)(?:that is|that's)\s+(?:enough|done)\.?\s*(?:now|please)\b`,
			core.ThreatInstructionOverride, 0.7,
			"task switching via 'that is done/enough, now...'",
		},
		{
			`(?i)\bnow\s+(?:concentrate|focus)\s+on\b`,
			core.ThreatInstructionOverride, 0.7,
			"redirection via 'now concentrate/focus on'",
		},
		{
			`(?i)(?:sehr\s+)?gut\s+(?:gemacht)?\.?\s*(?:das\s+)?(?:gen[uü]gt|ist\s+erledigt|reicht)`,
			core.ThreatInstructionOverride, 0.7,
			"German task switching via 'gut gemacht, das genügt' (well done, that's enough)",
		},
		{
			`(?i)\bausgezeichnete?\s+leistung\b`,
			core.ThreatInstructionOverride, 0.65,
			"German task switching via 'ausgezeichnete Leistung' (excellent performance)",
		},
		{
			`(?i)\bherzlichen\s+gl[uü]ckwunsch\b.*\b(?:aufgab|anweisung|prompt)\b`,
			core.ThreatInstructionOverride, 0.75,
			"German social engineering via congratulation + task reference",
		},
		{
			`(?i)\bACHTUNG\b.*\bSTOPP?\b`,
			core.ThreatInstructionOverride, 0.7,
			"German 'ACHTUNG STOPP' (attention stop)",
		},
		{
			`(?i)\bdu\s+bist\s+\w`,
			core.ThreatRoleManipulation, 0.45,
			"German role assignment via 'du bist' (you are)",
		},
		{
			`(?i)\bneu(?:e|en?)?\s+herausforderung\b`,
			core.ThreatInstructionOverride, 0.7,
			"German 'neue Herausforderung' (new challenge)",
		},
		{
			`(?i)\bbrauche\s+deine\s+hilfe\s+bei\s+(?:einer?\s+)?(?:weitere|andere)`,
			core.ThreatInstructionOverride, 0.7,
			"German 'brauche deine Hilfe bei einer weiteren' (need your help with another)",
		},
		{
			`(?i)\bim\s+stil(?:e)?\s+eine[sr]?\b`,
			core.ThreatRoleManipulation, 0.5,
			"German 'im Stile eines' (in the style of)",
		},
		{
			`(?i)\bANTWORTE\s+IM\s+STIL\b`,
			core.ThreatRoleManipulation, 0.6,
			"German 'ANTWORTE IM STIL' (answer in the style of)",
		},
		{
			`(?i)\bvorherigen?\s+informationen\b`,
			core.ThreatInstructionOverride, 0.7,
			"German reference to 'vorherige Informationen' (previous information)",
		},
		{
			`(?i)\bverfasse\s+nun\b`,
			core.ThreatInstructionOverride, 0.65,
			"German task switching via 'verfasse nun' (now compose)",
		},
		{
			`(?i)\bdas\s+ist\s+erledigt\b`,
			core.ThreatInstructionOverride, 0.6,
			"German task switching via 'das ist erledigt' (that is done)",
		},

		// ── role_manipulation ────────────────────────────────────────
		{
			`(?i)\byou\s+are\s+a\b`,
			core.ThreatRoleManipulation, 0.5,
			"potential role assignment via 'you are a'",
		},
		{
			`(?i)\bact\s+as\s+(a\s+|an\s+)?`,
			core.ThreatRoleManipulation, 0.6,
			"role manipulation via 'act as'",
		},
		{
			`(?i)\bpretend\s+(to\s+be|you\s+are|you're)\b`,
			core.ThreatRoleManipulation, 0.7,
			"role manipulation via 'pretend to be'",
		},
		{
			`(?i)\broleplay\s+as\b`,
			core.ThreatRoleManipulation, 0.7,
			"role manipulation via 'roleplay as'",
		},
		{
			`(?i)\bassume\s+the\s+role\s+of\b`,
			core.ThreatRoleManipulation, 0.7,
			"role manipulation via 'assume the role'",
		},
		{
			`(?i)\bswitch\s+to\s+(a\s+|an\s+)?(new\s+)?(role|persona|character|mode)\b`,
			core.ThreatRoleManipulation, 0.7,
			"role switch attempt",
		},
		{
			`(?i)\byour\s+new\s+role\b`,
			core.ThreatRoleManipulation, 0.75,
			"explicit new role assignment",
		},
		{
			`(?i)\bbehave\s+as\s+(a\s+|an\s+)?`,
			core.ThreatRoleManipulation, 0.6,
			"behavioural override via 'behave as'",
		},

		// ── delimiter_injection ──────────────────────────────────────
		{
			"(?i)```\\s*(system|user|assistant|human|ai)\\b",
			core.ThreatDelimiterInjection, 0.9,
			"markdown code fence with role delimiter",
		},
		{
			`(?i)<\|im_(start|end)\|>`,
			core.ThreatDelimiterInjection, 0.95,
			"ChatML delimiter injection",
		},
		{
			`(?i)</?system\s*>`,
			core.ThreatDelimiterInjection, 0.9,
			"XML-style system tag injection",
		},
		{
			`(?i)</?(?:user|assistant|human|ai)\s*>`,
			core.ThreatDelimiterInjection, 0.85,
			"XML-style role tag injection",
		},
		{
			`(?i)(?:^|\n)\s*###\s*(system|instruction|rule)`,
			core.ThreatDelimiterInjection, 0.7,
			"markdown heading as instruction delimiter",
		},
		{
			`(?i)(?:^|\n)\s*---+\s*\n\s*(system|instruction|new\s+rule)`,
			core.ThreatDelimiterInjection, 0.7,
			"horizontal rule as instruction delimiter",
		},

		// ── system_prompt_leak ───────────────────────────────────────
		{
			`(?i)\breveal\s+(your|the)?\s*(system\s+)?(instructions|prompt|rules|configuration)\b`,
			core.ThreatSystemPromptLeak, 0.85,
			"attempt to reveal system instructions",
		},
		{
			`(?i)\bshow\s+(me\s+)?(your|the)?\s*system\s+prompt\b`,
			core.ThreatSystemPromptLeak, 0.9,
			"attempt to show system prompt",
		},
		{
			`(?i)\bwhat\s+are\s+your\s+(rules|instructions|guidelines|directives)\b`,
			core.ThreatSystemPromptLeak, 0.7,
			"probing for system rules",
		},
		{
			`(?i)\brepeat\s+(your|the|all)?\s*(initial\s+)?(instructions|prompt|system\s+prompt|rules)\b`,
			core.ThreatSystemPromptLeak, 0.85,
			"attempt to repeat system instructions",
		},
		{
			`(?i)\boutput\s+(your|the)?\s*(initial|original|system)?\s*prompt\b`,
			core.ThreatSystemPromptLeak, 0.9,
			"attempt to output initial prompt",
		},
		{
			`(?i)\bwhat\s+were\s+you\s+told\b`,
			core.ThreatSystemPromptLeak, 0.75,
			"probing for initial instructions via 'what were you told'",
		},
	}

	defaultPatterns = make([]patternEntry, 0, len(raw))
	for _, r := range raw {
		defaultPatterns = append(defaultPatterns, patternEntry{
			re:          regexp.MustCompile(r.pattern),
			threatType:  r.threatType,
			severity:    r.severity,
			description: r.description,
		})
	}
}
