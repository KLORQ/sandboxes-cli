package command

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"

	"golang.org/x/term"
	"gopkg.in/yaml.v3"

	sdk "github.com/KLORQ/sandboxes-go-sdk"
)

var serviceSecretNames = []string{
	"anthropic", "copilot", "cursor", "devin", "droid", "github", "google",
	"groq", "mistral", "nebius", "openai", "openrouter", "xai",
}

type serviceSecretOutput struct {
	Type        string `json:"type" yaml:"type"`
	Service     string `json:"service" yaml:"service"`
	Username    string `json:"username,omitempty" yaml:"username,omitempty"`
	Scope       string `json:"scope" yaml:"scope"`
	SandboxName string `json:"sandbox_name,omitempty" yaml:"sandbox_name,omitempty"`
	State       string `json:"state" yaml:"state"`
}

func (r *Runner) serviceSecretSet(ctx context.Context, args []string) int {
	args = reorderFlagArgs(args, map[string]bool{"--sandbox": true, "--token": true, "--ref": true, "--command": true})
	fs := flag.NewFlagSet("secret set", flag.ContinueOnError)
	fs.SetOutput(r.Err)
	sandboxName := fs.String("sandbox", "", "scope the secret to one sandbox")
	token := fs.String("token", "", "secret value (less secure: visible in shell history)")
	ref := fs.String("ref", "", "secret reference (not implemented)")
	command := fs.String("command", "", "secret command (not implemented)")
	if code, done := r.parseFlagsOrFail("secret set", fs, args); done {
		return code
	}
	if fs.NArg() != 1 {
		_, _ = fmt.Fprintln(r.Err, "usage: ksbx secret set SERVICE [--sandbox NAME] [--token VALUE]")
		return 2
	}
	service := strings.ToLower(fs.Arg(0))
	if !validServiceSecret(service) {
		r.error(fmt.Errorf("unknown service %q; use one of: %s", service, strings.Join(serviceSecretNames, ", ")))
		return 2
	}
	if *ref != "" || *command != "" {
		r.error(errors.New("--ref and --command are not implemented by the local broker"))
		return 2
	}
	value := []byte(*token)
	if len(value) == 0 {
		read, err := r.readServiceSecret()
		if err != nil {
			r.error(err)
			return 2
		}
		value = read
	}
	defer clear(value)
	scope := sdk.SecretScopeGlobal
	if *sandboxName != "" {
		scope = sdk.SecretScopeSandbox
	}
	client, err := r.client()
	if err != nil {
		r.error(err)
		return 1
	}
	defer func() { _ = client.Close() }()
	summary, err := sdk.Secrets(client).Set(ctx, service, scope, *sandboxName, value)
	if err != nil {
		r.error(err)
		return 1
	}
	sandbox := summary.SandboxName
	if sandbox == "" {
		sandbox = ""
	}
	_, _ = fmt.Fprintf(r.Out, "Stored %s secret for %s (%s) in host keychain; it is not injected into sandboxes yet\n", summary.Service, summary.Scope, sandbox)
	return 0
}

func (r *Runner) readServiceSecret() ([]byte, error) {
	if file, ok := r.In.(*os.File); ok && term.IsTerminal(int(file.Fd())) {
		if _, err := fmt.Fprint(r.Err, "Secret: "); err != nil {
			return nil, fmt.Errorf("write secret prompt: %w", err)
		}
		value, err := term.ReadPassword(int(file.Fd()))
		_, _ = fmt.Fprintln(r.Err)
		if err != nil {
			return nil, fmt.Errorf("read secret: %w", err)
		}
		if len(value) == 0 || len(value) > 8192 {
			clear(value)
			return nil, errors.New("secret must be 1 to 8192 bytes")
		}
		return value, nil
	}
	value, err := io.ReadAll(io.LimitReader(r.In, 8193))
	if err != nil {
		clear(value)
		return nil, fmt.Errorf("read secret from stdin: %w", err)
	}
	if len(value) > 8192 {
		clear(value)
		return nil, errors.New("secret exceeds the 8192-byte limit")
	}
	value = bytes.TrimSuffix(bytes.TrimSuffix(value, []byte("\n")), []byte("\r"))
	if len(value) == 0 || bytes.ContainsAny(value, "\r\n") {
		clear(value)
		return nil, errors.New("secret input must contain one non-empty line")
	}
	return value, nil
}

func validServiceSecret(service string) bool {
	for _, candidate := range serviceSecretNames {
		if service == candidate {
			return true
		}
	}
	return false
}

func (r *Runner) serviceSecretRemove(ctx context.Context, args []string) int {
	args = reorderFlagArgs(args, map[string]bool{"--sandbox": true})
	fs := flag.NewFlagSet("secret rm", flag.ContinueOnError)
	fs.SetOutput(r.Err)
	sandboxName := fs.String("sandbox", "", "scope the secret to one sandbox")
	if code, done := r.parseFlagsOrFail("secret rm", fs, args); done {
		return code
	}
	if fs.NArg() != 1 {
		_, _ = fmt.Fprintln(r.Err, "usage: ksbx secret rm SERVICE [--sandbox NAME]")
		return 2
	}
	scope := sdk.SecretScopeGlobal
	if *sandboxName != "" {
		scope = sdk.SecretScopeSandbox
	}
	client, err := r.client()
	if err != nil {
		r.error(err)
		return 1
	}
	defer func() { _ = client.Close() }()
	removed, err := sdk.Secrets(client).Remove(ctx, strings.ToLower(fs.Arg(0)), scope, *sandboxName)
	if err != nil {
		r.error(err)
		return 1
	}
	if removed {
		_, _ = fmt.Fprintf(r.Out, "Removed %s secret\n", fs.Arg(0))
	} else {
		_, _ = fmt.Fprintf(r.Out, "No %s secret stored\n", fs.Arg(0))
	}
	return 0
}

//nolint:gocognit,gocyclo,cyclop,funlen // one command renders two credential types and three formats.
func (r *Runner) serviceSecretList(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("secret ls", flag.ContinueOnError)
	fs.SetOutput(r.Err)
	format := fs.String("format", listFormatTable, "output format: table, json or yaml")
	jsonOutput := fs.Bool("json", false, "output in JSON format")
	if code, done := r.parseFlagsOrFail("secret ls", fs, args); done {
		return code
	}
	if fs.NArg() != 0 {
		_, _ = fmt.Fprintln(r.Err, "usage: ksbx secret ls [--format table|json|yaml]")
		return 2
	}
	selected, err := resolveOperationFormat(*format, *jsonOutput)
	if err != nil {
		r.error(err)
		return 2
	}
	client, err := r.client()
	if err != nil {
		r.error(err)
		return 1
	}
	defer func() { _ = client.Close() }()
	out := make([]serviceSecretOutput, 0, 4)
	items, err := sdk.Secrets(client).List(ctx)
	if err != nil {
		var sdkErr *sdk.Error
		if !errors.As(err, &sdkErr) || sdkErr.Code != "unsupported" {
			r.error(err)
			return 1
		}
	}
	for _, item := range items {
		out = append(out, serviceSecretOutput{Type: "service", Service: item.Service, Scope: string(item.Scope), SandboxName: item.SandboxName, State: "(stored)"})
	}
	if lister, ok := sdk.RegistryCredentialList(client); ok {
		registries, regErr := lister.ListRegistryCredentials(ctx)
		if regErr != nil {
			r.error(regErr)
			return 1
		}
		for _, item := range registries {
			out = append(out, serviceSecretOutput{Type: "registry", Service: item.Registry, Username: item.Username, Scope: item.Scope, SandboxName: item.SandboxName, State: "(stored)"})
		}
	}
	switch selected {
	case listFormatTable:
		if len(out) == 0 {
			_, _ = fmt.Fprintln(r.Out, "No secrets stored")
			return 0
		}
		tw := tabwriter.NewWriter(r.Out, 0, 4, 2, ' ', 0)
		_, _ = fmt.Fprintln(tw, "TYPE\tSERVICE\tUSERNAME\tSCOPE\tSANDBOX\tSECRET")
		for _, item := range out {
			sandbox := item.SandboxName
			if sandbox == "" {
				sandbox = "(global)"
			}
			username := item.Username
			if username == "" {
				username = "-"
			}
			_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", item.Type, item.Service, username, item.Scope, sandbox, item.State)
		}
		if err := tw.Flush(); err != nil {
			r.error(err)
			return 1
		}
		return 0
	case listFormatYAML:
		data, err := yaml.Marshal(out)
		if err != nil {
			r.error(err)
			return 1
		}
		_, _ = r.Out.Write(data)
		return 0
	default:
		encoder := json.NewEncoder(r.Out)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(out); err != nil {
			r.error(err)
			return 1
		}
		return 0
	}
}
