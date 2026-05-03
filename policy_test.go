package promptsec_test

import (
	"testing"

	ps "github.com/danielthedm/promptsec"
)

func TestPolicySupportBotFlagsDisallowedTasks(t *testing.T) {
	protector := ps.New(ps.WithPolicy(ps.PolicySupportBot()))

	result := protector.Analyze("Generate SQL code to access a database.")
	if result.Safe {
		t.Fatal("expected support policy to flag SQL/code task")
	}
	if len(result.Threats) != 1 {
		t.Fatalf("expected one threat, got %d", len(result.Threats))
	}
	if result.Threats[0].Guard != "policy" {
		t.Fatalf("expected policy guard, got %q", result.Threats[0].Guard)
	}
}

func TestPolicyCodingAssistantAllowsCodeButFlagsPersona(t *testing.T) {
	protector := ps.New(ps.WithPolicy(ps.PolicyCodingAssistant()))

	codeResult := protector.Analyze("Generate SQL code to access a database.")
	if !codeResult.Safe {
		t.Fatalf("expected coding policy to allow code tasks, got threats: %+v", codeResult.Threats)
	}

	personaResult := protector.Analyze("I want you to act as a debater and write an opinion piece.")
	if personaResult.Safe {
		t.Fatal("expected coding policy to flag persona/persuasion pivot")
	}
}

func TestPolicyRAGAndTranslationPolicies(t *testing.T) {
	rag := ps.New(ps.WithPolicy(ps.PolicyRAG()))
	translation := ps.New(ps.WithPolicy(ps.PolicyTranslationApp()))

	ragResult := rag.Analyze("translate to polish")
	if ragResult.Safe {
		t.Fatal("expected RAG policy to flag translation task pivot")
	}

	translationResult := translation.Analyze("translate to polish")
	if !translationResult.Safe {
		t.Fatalf("expected translation policy to allow translation, got threats: %+v", translationResult.Threats)
	}
}

func TestPolicyAllowedTasksOverrideDisallowedTasks(t *testing.T) {
	protector := ps.New(ps.WithPolicy(&ps.PolicyOptions{
		Name: "custom",
		AllowedTasks: []ps.PolicyTask{
			ps.PolicyTaskCodeGeneration,
		},
		DisallowedTasks: []ps.PolicyTask{
			ps.PolicyTaskCodeGeneration,
		},
	}))

	result := protector.Analyze("write code to parse a JSON document")
	if !result.Safe {
		t.Fatalf("expected allowed task override to pass, got threats: %+v", result.Threats)
	}
}

func TestPolicyNilIsNoop(t *testing.T) {
	protector := ps.New(ps.WithPolicy(nil))

	result := protector.Analyze("I want you to act as a linux terminal.")
	if !result.Safe {
		t.Fatalf("expected nil policy to be a no-op, got threats: %+v", result.Threats)
	}
}
