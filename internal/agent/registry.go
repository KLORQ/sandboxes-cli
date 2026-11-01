// Package agent defines the built-in sandbox agent registry.
package agent

import (
	_ "embed"
	"fmt"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Status controls whether an agent may be launched.
type Status string

const (
	StatusAvailable   Status = "available"
	StatusPreview     Status = "preview"
	StatusUnsupported Status = "unsupported"
)

// Spec is one built-in agent definition.
type Spec struct {
	Name    string   `yaml:"name"`
	Image   string   `yaml:"image"`
	Command []string `yaml:"command"`
	Status  Status   `yaml:"status"`
	Docker  bool     `yaml:"docker,omitempty"`
	Notes   string   `yaml:"notes,omitempty"`
}

// Registry is an immutable agent set.
type Registry struct {
	byName map[string]Spec
	names  []string
}

//go:embed registry.yaml
var registryYAML []byte

// Load parses and validates the built-in registry.
func Load() (*Registry, error) {
	var doc struct {
		Agents []Spec `yaml:"agents"`
	}
	if err := yaml.Unmarshal(registryYAML, &doc); err != nil {
		return nil, fmt.Errorf("parse agent registry: %w", err)
	}
	r := &Registry{byName: make(map[string]Spec, len(doc.Agents))}
	for _, spec := range doc.Agents {
		spec.Name = strings.TrimSpace(spec.Name)
		if spec.Name == "" {
			return nil, fmt.Errorf("agent registry contains an empty name")
		}
		if _, exists := r.byName[spec.Name]; exists {
			return nil, fmt.Errorf("duplicate agent %q", spec.Name)
		}
		switch spec.Status {
		case StatusAvailable, StatusPreview:
			if len(spec.Command) == 0 {
				return nil, fmt.Errorf("agent %q has no command", spec.Name)
			}
		case StatusUnsupported:
		default:
			return nil, fmt.Errorf("agent %q has unknown status %q", spec.Name, spec.Status)
		}
		r.byName[spec.Name] = spec
		r.names = append(r.names, spec.Name)
	}
	sort.Strings(r.names)
	return r, nil
}

// Lookup returns an agent by exact name.
func (r *Registry) Lookup(name string) (Spec, bool) {
	spec, ok := r.byName[name]
	return spec, ok
}

// Names returns all registered names in sorted order.
func (r *Registry) Names() []string { return append([]string(nil), r.names...) }

// Launchable reports whether the agent may be launched.
func (s Spec) Launchable() bool {
	return s.Status == StatusAvailable || s.Status == StatusPreview
}
