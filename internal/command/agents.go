package command

import (
	"fmt"
	"sync"

	"github.com/KLORQ/sandboxes-cli/internal/agent"
)

var loadAgentRegistry = sync.OnceValues(agent.Load)

func agentRegistry() (*agent.Registry, error) {
	return loadAgentRegistry()
}

func agentImage(name string) string {
	registry, err := agentRegistry()
	if err != nil {
		return ""
	}
	spec, ok := registry.Lookup(name)
	if !ok {
		return ""
	}
	return spec.Image
}

func agentDocker(name string) bool {
	registry, err := agentRegistry()
	if err != nil {
		return false
	}
	spec, ok := registry.Lookup(name)
	return ok && spec.Docker
}

func agentCommand(name string) string {
	registry, err := agentRegistry()
	if err != nil {
		return name
	}
	spec, ok := registry.Lookup(name)
	if !ok || len(spec.Command) == 0 {
		return name
	}
	return spec.Command[0]
}

func agentCommandArgs(name string) []string {
	registry, err := agentRegistry()
	if err != nil {
		return []string{name}
	}
	spec, ok := registry.Lookup(name)
	if !ok || len(spec.Command) == 0 {
		return []string{name}
	}
	return append([]string(nil), spec.Command...)
}

func validateAgent(name string) error {
	registry, err := agentRegistry()
	if err != nil {
		return fmt.Errorf("load agent registry: %w", err)
	}
	spec, ok := registry.Lookup(name)
	if !ok {
		return fmt.Errorf("unknown agent %q; use one of: %v", name, registry.Names())
	}
	if !spec.Launchable() {
		return fmt.Errorf("agent %q is not implemented yet; status %s", name, spec.Status)
	}
	return nil
}
