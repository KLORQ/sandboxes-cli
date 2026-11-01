// Package kit parses local Klorq kit files.
package kit

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Kit is a local, unsigned kit definition. Remote OCI kits and signatures are
// deliberately out of scope for this parser.
type Kit struct {
	APIVersion string   `yaml:"apiVersion"`
	Kind       string   `yaml:"kind"`
	Metadata   Metadata `yaml:"metadata"`
	Spec       Spec     `yaml:"spec"`
}

// Metadata identifies a kit.
type Metadata struct {
	Name string `yaml:"name"`
}

// Spec is the runnable kit configuration.
type Spec struct {
	Agent         string    `yaml:"agent"`
	Image         string    `yaml:"image"`
	PolicyProfile string    `yaml:"policy_profile"`
	Workspace     Workspace `yaml:"workspace"`
	MCP           MCP       `yaml:"mcp"`
	Mounts        []Mount   `yaml:"mounts"`
}

// Workspace is a first-start workspace seed. Seed is not implemented yet and
// must be empty so a kit cannot silently skip its checkout.
type Workspace struct {
	Seed string `yaml:"seed"`
}

// MCP is an MCP allowlist. It is parsed but not applied until the MCP gateway
// exists, so a non-empty allowlist fails closed.
type MCP struct {
	Allow []string `yaml:"allow"`
}

// Mount is an additional host workspace.
type Mount struct {
	Path     string `yaml:"path"`
	ReadOnly bool   `yaml:"read_only"`
}

// Load reads one local kit file with unknown fields rejected.
func Load(path string) (Kit, error) {
	file, err := os.Open(path) // #nosec G304 -- user-selected local kit path
	if err != nil {
		return Kit{}, fmt.Errorf("open kit: %w", err)
	}
	defer func() { _ = file.Close() }()
	return Decode(file)
}

// Decode parses a kit from r.
func Decode(r io.Reader) (Kit, error) {
	decoder := yaml.NewDecoder(r)
	decoder.KnownFields(true)
	var doc Kit
	if err := decoder.Decode(&doc); err != nil {
		return Kit{}, fmt.Errorf("parse kit: %w", err)
	}
	if err := doc.Validate(); err != nil {
		return Kit{}, err
	}
	return doc, nil
}

// Validate checks the stable local subset.
func (k Kit) Validate() error {
	if k.APIVersion != "klorq.dev/v1alpha1" {
		return fmt.Errorf("unsupported kit apiVersion %q", k.APIVersion)
	}
	if k.Kind != "Kit" {
		return fmt.Errorf("kit kind must be Kit, got %q", k.Kind)
	}
	if strings.TrimSpace(k.Metadata.Name) == "" || len(k.Metadata.Name) > 63 {
		return errors.New("kit metadata.name is required (maximum 63 characters)")
	}
	if k.Spec.Agent == "" && k.Spec.Image == "" {
		return errors.New("kit spec.agent or spec.image is required")
	}
	switch k.Spec.PolicyProfile {
	case "", "deny-all", "balanced", "sbx-compat":
	default:
		return errors.New("kit spec.policy_profile must be deny-all, balanced or sbx-compat")
	}
	if k.Spec.Workspace.Seed != "" {
		return errors.New("kit workspace.seed is not implemented by the local runtime")
	}
	if len(k.Spec.MCP.Allow) != 0 {
		return errors.New("kit mcp.allow is not implemented by the local runtime")
	}
	for _, mount := range k.Spec.Mounts {
		if mount.Path == "" || !strings.HasPrefix(mount.Path, "/") {
			return errors.New("kit mount paths must be absolute")
		}
	}
	return nil
}

// Paths returns mount paths with the conventional :ro suffix.
func (k Kit) Paths() []string {
	out := make([]string, 0, len(k.Spec.Mounts))
	for _, mount := range k.Spec.Mounts {
		path := mount.Path
		if mount.ReadOnly {
			path += ":ro"
		}
		out = append(out, path)
	}
	return out
}
