package command

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	sdk "github.com/KLORQ/sandboxes-go-sdk"
)

var serviceEnvVars = map[string][]string{
	"anthropic":  {"ANTHROPIC_API_KEY"},
	"copilot":    {"COPILOT_API_KEY"},
	"cursor":     {"CURSOR_API_KEY"},
	"devin":      {"DEVIN_API_KEY"},
	"droid":      {"DROID_API_KEY"},
	"github":     {"GH_TOKEN", "GITHUB_TOKEN"},
	"google":     {"GOOGLE_API_KEY", "GEMINI_API_KEY"},
	"groq":       {"GROQ_API_KEY"},
	"mistral":    {"MISTRAL_API_KEY"},
	"nebius":     {"NEBIUS_API_KEY"},
	"openai":     {"OPENAI_API_KEY"},
	"openrouter": {"OPENROUTER_API_KEY"},
	"xai":        {"XAI_API_KEY"},
}

//nolint:gocognit,gocyclo,cyclop,funlen // interactive import intentionally handles each branch explicitly.
func (r *Runner) serviceSecretImport(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("secret import", flag.ContinueOnError)
	fs.SetOutput(r.Err)
	all := fs.Bool("all", false, "import every detected variable without prompting")
	force := fs.Bool("force", false, "overwrite existing secrets")
	dryRun := fs.Bool("dry-run", false, "show what would be imported")
	if code, done := r.parseFlagsOrFail("secret import", fs, args); done {
		return code
	}
	if fs.NArg() > 1 {
		_, _ = fmt.Fprintln(r.Err, "usage: ksbx secret import [SERVICE] [--all] [--force] [--dry-run]")
		return 2
	}
	requested := ""
	if fs.NArg() == 1 {
		requested = strings.ToLower(fs.Arg(0))
		if !validServiceSecret(requested) {
			r.error(fmt.Errorf("unknown service %q", requested))
			return 2
		}
	}
	client, err := r.client()
	if err != nil {
		r.error(err)
		return 1
	}
	defer func() { _ = client.Close() }()
	existing := make(map[string]bool)
	if !*force {
		if items, err := sdk.Secrets(client).List(ctx); err == nil {
			for _, item := range items {
				if item.Scope == sdk.SecretScopeGlobal {
					existing[item.Service] = true
				}
			}
		}
	}
	imported := 0
	for _, service := range serviceSecretNames {
		if requested != "" && service != requested {
			continue
		}
		name, value := lookupServiceEnv(service)
		if name == "" {
			continue
		}
		if existing[service] && !*force {
			_, _ = fmt.Fprintf(r.Err, "skip %s: already stored (use --force)\n", service)
			continue
		}
		if *dryRun {
			_, _ = fmt.Fprintf(r.Out, "would import %s from %s\n", service, name)
			continue
		}
		if !*all {
			ok, err := r.confirmSecretImport(service, name, value)
			if err != nil {
				r.error(err)
				return 1
			}
			if !ok {
				continue
			}
		}
		if _, err := sdk.Secrets(client).Set(ctx, service, sdk.SecretScopeGlobal, "", []byte(value)); err != nil {
			r.error(err)
			return 1
		}
		imported++
		_, _ = fmt.Fprintf(r.Out, "imported %s from %s\n", service, name)
	}
	if requested != "" && imported == 0 && !*dryRun {
		_, _ = fmt.Fprintf(r.Err, "no environment variable found for %s\n", requested)
	}
	return 0
}

func lookupServiceEnv(service string) (string, string) {
	for _, name := range serviceEnvVars[service] {
		if value := os.Getenv(name); value != "" {
			return name, value
		}
	}
	return "", ""
}

func (r *Runner) confirmSecretImport(service, name, value string) (bool, error) {
	preview := "****"
	if len(value) >= 4 {
		preview = "****" + value[len(value)-4:]
	}
	if _, err := fmt.Fprintf(r.Err, "Import %s from %s (%s)? [y/N] ", service, name, preview); err != nil {
		return false, err
	}
	var answer string
	if _, err := fmt.Fscanln(r.In, &answer); err != nil && !errors.Is(err, os.ErrClosed) {
		if strings.Contains(err.Error(), "EOF") {
			return false, nil
		}
		return false, err
	}
	answer = strings.ToLower(strings.TrimSpace(answer))
	return answer == answerShortYes || answer == answerYes, nil
}
