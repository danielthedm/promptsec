package core

import "time"

type Context struct {
	RawInput   string
	Input      string
	Threats    []Threat
	Metadata   map[string]any
	TrustLevel TrustLevel
	Halted     bool
	StartTime  time.Time
}

func NewContext(input string) *Context {
	return &Context{
		RawInput:   input,
		Input:      input,
		Threats:    nil,
		Metadata:   make(map[string]any),
		TrustLevel: Unknown,
		StartTime:  time.Now(),
	}
}

func (c *Context) AddThreat(t Threat) {
	c.Threats = append(c.Threats, t)
}

func (c *Context) Halt() {
	c.Halted = true
}

func (c *Context) SetMeta(key string, value any) {
	c.Metadata[key] = value
}

func (c *Context) GetMeta(key string) (any, bool) {
	v, ok := c.Metadata[key]
	return v, ok
}

func (c *Context) MaxSeverity() float64 {
	max := 0.0
	for _, t := range c.Threats {
		if t.Severity > max {
			max = t.Severity
		}
	}
	return max
}

func (c *Context) HasThreatType(tt ThreatType) bool {
	for _, t := range c.Threats {
		if t.Type == tt {
			return true
		}
	}
	return false
}

func (c *Context) Elapsed() time.Duration {
	return time.Since(c.StartTime)
}
