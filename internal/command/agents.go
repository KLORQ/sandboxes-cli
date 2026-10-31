package command

// agentSpec describes a built-in coding agent. Image is used only when the
// caller did not pass an explicit --image.
type agentSpec struct {
	Name    string
	Image   string
	Command string
}

const (
	kimiAgent = "kimi"
	kimiImage = "ghcr.io/klorq/sandbox-kimi:0.43.0"
)

var agentSpecs = map[string]agentSpec{
	shellAgent: {Name: shellAgent, Command: shellPath},
	kimiAgent:  {Name: kimiAgent, Image: kimiImage, Command: "kimi"},
}

func agentSpecFor(name string) (agentSpec, bool) {
	spec, ok := agentSpecs[name]
	return spec, ok
}

func agentImage(name string) string {
	if spec, ok := agentSpecFor(name); ok {
		return spec.Image
	}
	return ""
}

func agentCommand(name string) string {
	if spec, ok := agentSpecFor(name); ok && spec.Command != "" {
		return spec.Command
	}
	return name
}
