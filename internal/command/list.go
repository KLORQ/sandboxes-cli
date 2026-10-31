package command

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"text/tabwriter"
	"time"

	"gopkg.in/yaml.v3"

	sdk "github.com/KLORQ/sandboxes-go-sdk"
)

const listUsage = `usage: ksbx ls [--format table|json|yaml] [--json] [-q] [--limit N]

List sandboxes. table is the default; --json is equivalent to --format json;
-q prints only names. JSON/YAML fields include name, id, agent, status,
last_used_at, workspaces, created_at and detached.`

const (
	listFormatTable = "table"
	listFormatJSON  = "json"
	listFormatYAML  = "yaml"
)

type listOptions struct {
	limit  int
	format string
	quiet  bool
}

type sandboxOutput struct {
	Name          string       `json:"name" yaml:"name"`
	ID            string       `json:"id" yaml:"id"`
	Agent         string       `json:"agent" yaml:"agent"`
	Status        string       `json:"status" yaml:"status"`
	LastUsedAt    string       `json:"last_used_at,omitempty" yaml:"last_used_at,omitempty"`
	Detached      bool         `json:"detached,omitempty" yaml:"detached,omitempty"`
	PolicyProfile string       `json:"policy_profile,omitempty" yaml:"policy_profile,omitempty"`
	Image         string       `json:"image" yaml:"image"`
	Workspaces    []string     `json:"workspaces" yaml:"workspaces"`
	Ports         []portOutput `json:"ports" yaml:"ports"`
	Allow         []ruleOutput `json:"allow" yaml:"allow"`
	Deny          []ruleOutput `json:"deny" yaml:"deny"`
	CPUs          uint32       `json:"cpus" yaml:"cpus"`
	MemoryMiB     uint32       `json:"memory_mib" yaml:"memory_mib"`
	StoppedAt     string       `json:"stopped_at,omitempty" yaml:"stopped_at,omitempty"`
	Generation    int64        `json:"generation" yaml:"generation"`
	CreatedAt     string       `json:"created_at" yaml:"created_at"`
	UpdatedAt     string       `json:"updated_at" yaml:"updated_at"`
}

func (r *Runner) list(ctx context.Context, args []string) int {
	opts, help, err := parseListOptions(args)
	if help {
		_, _ = fmt.Fprint(r.Out, listUsage)
		return 0
	}
	if err != nil {
		_, _ = fmt.Fprintf(r.Err, "ksbx ls: %v\n", err)
		return 2
	}
	client, err := r.client()
	if err != nil {
		r.error(err)
		return 1
	}
	defer func() { _ = client.Close() }()
	items, err := collectSandboxes(ctx, client, opts.limit)
	if err != nil {
		r.error(err)
		return 1
	}
	if opts.quiet {
		for i := range items {
			_, _ = fmt.Fprintln(r.Out, items[i].Name)
		}
		return 0
	}
	if err := renderSandboxes(r.Out, opts.format, items); err != nil {
		r.error(err)
		return 1
	}
	return 0
}

func parseListOptions(args []string) (listOptions, bool, error) {
	fs := flag.NewFlagSet("ls", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	limit := fs.Int("limit", 50, "page size")
	format := fs.String("format", listFormatTable, "output format: table, json or yaml")
	jsonOutput := fs.Bool("json", false, "output in JSON format")
	quiet := fs.Bool("q", false, "only display sandbox names")
	fs.BoolVar(quiet, "quiet", false, "only display sandbox names")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return listOptions{}, true, nil
		}
		return listOptions{}, false, err
	}
	if fs.NArg() != 0 {
		return listOptions{}, false, errors.New("usage: ksbx ls [--format table|json|yaml] [--json] [-q] [--limit N]")
	}
	selected := *format
	if *jsonOutput {
		if *format != listFormatTable {
			return listOptions{}, false, errors.New("--json cannot be combined with an explicit --format")
		}
		selected = listFormatJSON
	}
	if selected != listFormatTable && selected != listFormatJSON && selected != listFormatYAML {
		return listOptions{}, false, fmt.Errorf("invalid format %q; use table, json or yaml", selected)
	}
	if *quiet && selected != listFormatTable {
		return listOptions{}, false, errors.New("--quiet cannot be combined with a non-table format")
	}
	if *limit <= 0 || *limit > 1000 {
		return listOptions{}, false, errors.New("--limit must be between 1 and 1000")
	}
	return listOptions{limit: *limit, format: selected, quiet: *quiet}, false, nil
}

func collectSandboxes(ctx context.Context, client sdk.Client, limit int) ([]sdk.Sandbox, error) {
	items := make([]sdk.Sandbox, 0, limit)
	seen := make(map[string]struct{})
	token := ""
	for pages := 0; pages < 10000; pages++ {
		page, err := client.Sandboxes().List(ctx, sdk.ListOptions{PageSize: limit, PageToken: token})
		if err != nil {
			return nil, err
		}
		items = append(items, page.Items...)
		if page.NextPageToken == "" {
			return items, nil
		}
		if _, exists := seen[page.NextPageToken]; exists {
			return nil, errors.New("invalid sandbox pagination")
		}
		seen[page.NextPageToken] = struct{}{}
		token = page.NextPageToken
	}
	return nil, errors.New("too many sandbox pages")
}

func renderSandboxes(out io.Writer, format string, items []sdk.Sandbox) error {
	switch format {
	case listFormatJSON:
		encoder := json.NewEncoder(out)
		encoder.SetIndent("", "  ")
		return encoder.Encode(sandboxOutputs(items))
	case listFormatYAML:
		data, err := yaml.Marshal(sandboxOutputs(items))
		if err != nil {
			return err
		}
		_, err = out.Write(data)
		return err
	default:
		return writeSandboxTable(out, items)
	}
}

func sandboxOutputs(items []sdk.Sandbox) []sandboxOutput {
	output := make([]sandboxOutput, 0, len(items))
	for i := range items {
		output = append(output, sandboxOutputFor(&items[i]))
	}
	return output
}

func sandboxOutputFor(sb *sdk.Sandbox) sandboxOutput {
	workspaces := make([]string, 0, len(sb.Workspaces)+1)
	if len(sb.Workspaces) > 0 {
		workspaces = append(workspaces, workspacePaths(sb.Workspaces)...)
	} else if sb.Workspace != "" {
		workspaces = append(workspaces, sb.Workspace)
	}
	return sandboxOutput{
		Name:          sb.Name,
		ID:            sb.ID,
		Agent:         sb.Agent,
		Status:        sb.State,
		LastUsedAt:    listTime(sb.LastUsedAt),
		Detached:      sb.Detached,
		PolicyProfile: sb.PolicyProfile,
		Image:         sb.Image,
		Workspaces:    workspaces,
		Ports:         portsFor(sb),
		Allow:         allowRules(sb),
		Deny:          denyRules(sb),
		CPUs:          sb.CPUs,
		MemoryMiB:     sb.MemoryMiB,
		StoppedAt:     listTime(sb.StoppedAt),
		Generation:    sb.Generation,
		CreatedAt:     listTime(sb.CreatedAt),
		UpdatedAt:     listTime(sb.UpdatedAt),
	}
}

func listTime(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format(time.RFC3339Nano)
}

func writeSandboxTable(out io.Writer, items []sdk.Sandbox) error {
	tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "SANDBOX\tAGENT\tPROFILE\tSTATUS\tPORTS\tWORKSPACE\tCREATED")
	for i := range items {
		sb := &items[i]
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", sb.Name, formatAgent(sb.Agent), formatProfile(sb.PolicyProfile), sb.State, formatPorts(sb), formatWorkspaces(sb), formatAge(sb.CreatedAt))
	}
	return tw.Flush()
}

func formatProfile(profile string) string {
	if profile == "" {
		return "-"
	}
	return profile
}

func formatAgent(agent string) string {
	if agent == "" {
		return "-"
	}
	return agent
}

func formatAge(created time.Time) string {
	if created.IsZero() {
		return "-"
	}
	age := time.Since(created)
	if age < 0 {
		age = 0
	}
	switch {
	case age < time.Minute:
		return "now"
	case age < time.Hour:
		return fmt.Sprintf("%dm", int(age.Minutes()))
	case age < 24*time.Hour:
		return fmt.Sprintf("%dh", int(age.Hours()))
	default:
		return fmt.Sprintf("%dd", int(age.Hours()/24))
	}
}
