package core

import (
	"fmt"
	"strings"
)

type InjectionError struct {
	Threats []Threat
}

func (e *InjectionError) Error() string {
	if len(e.Threats) == 0 {
		return "prompt injection detected"
	}
	msgs := make([]string, len(e.Threats))
	for i, t := range e.Threats {
		msgs[i] = fmt.Sprintf("[%s] %s (severity=%.2f)", t.Type, t.Message, t.Severity)
	}
	return fmt.Sprintf("prompt injection detected: %s", strings.Join(msgs, "; "))
}

func NewInjectionError(threats []Threat) *InjectionError {
	return &InjectionError{Threats: threats}
}
