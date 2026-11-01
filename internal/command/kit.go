package command

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"gopkg.in/yaml.v3"

	"github.com/KLORQ/sandboxes-cli/internal/kit"
)

const kitUsage = `Usage: ksbx kit COMMAND

Manage local kit files (klorq.dev/v1alpha1). Kits are unsigned local files;
remote OCI kits, seeds, signatures and MCP allowlists are not implemented yet.

Commands:
  inspect FILE [--format table|json|yaml]   validate and print a kit
  ls [DIR]                                  list local .yaml kits
`

func (r *Runner) kit(args []string) int {
	if len(args) == 0 {
		_, _ = fmt.Fprint(r.Err, kitUsage)
		return 2
	}
	switch args[0] {
	case helpCommand, helpShort, helpFlag:
		_, _ = fmt.Fprint(r.Out, kitUsage)
		return 0
	case commandInspect:
		return r.kitInspect(args[1:])
	case "ls", "list":
		return r.kitList(args[1:])
	default:
		_, _ = fmt.Fprintf(r.Err, "ksbx kit: unknown subcommand %q\n", args[0])
		return 2
	}
}

func (r *Runner) kitInspect(args []string) int {
	fs := flag.NewFlagSet("kit inspect", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	format := fs.String("format", listFormatTable, "output format: table, json or yaml")
	jsonOutput := fs.Bool("json", false, "output in JSON format")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return r.flagParseFailure("kit inspect", err)
	}
	if fs.NArg() != 1 {
		_, _ = fmt.Fprintln(r.Err, "usage: ksbx kit inspect FILE [--format table|json|yaml]")
		return 2
	}
	selected, err := resolveOperationFormat(*format, *jsonOutput)
	if err != nil {
		r.error(err)
		return 2
	}
	doc, err := kit.Load(fs.Arg(0))
	if err != nil {
		r.error(err)
		return 1
	}
	switch selected {
	case listFormatTable:
		tw := tabwriter.NewWriter(r.Out, 0, 4, 2, ' ', 0)
		_, _ = fmt.Fprintln(tw, "NAME\tAGENT\tIMAGE\tPROFILE\tMOUNTS")
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", doc.Metadata.Name, doc.Spec.Agent, doc.Spec.Image, doc.Spec.PolicyProfile, strings.Join(doc.Paths(), ","))
		if err := tw.Flush(); err != nil {
			r.error(err)
			return 1
		}
		return 0
	case listFormatYAML:
		data, err := yaml.Marshal(doc)
		if err != nil {
			r.error(err)
			return 1
		}
		_, _ = r.Out.Write(data)
		return 0
	default:
		encoder := json.NewEncoder(r.Out)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(doc); err != nil {
			r.error(err)
			return 1
		}
		return 0
	}
}

func (r *Runner) kitList(args []string) int {
	if len(args) > 1 {
		_, _ = fmt.Fprintln(r.Err, "usage: ksbx kit ls [DIR]")
		return 2
	}
	dir := "."
	if len(args) == 1 {
		dir = args[0]
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		r.error(err)
		return 1
	}
	tw := tabwriter.NewWriter(r.Out, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "FILE\tNAME\tAGENT\tPROFILE")
	found := 0
	for _, entry := range entries {
		if entry.IsDir() || (!strings.HasSuffix(entry.Name(), ".yaml") && !strings.HasSuffix(entry.Name(), ".yml")) {
			continue
		}
		doc, err := kit.Load(filepath.Join(dir, entry.Name()))
		if err != nil {
			continue
		}
		found++
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", entry.Name(), doc.Metadata.Name, doc.Spec.Agent, doc.Spec.PolicyProfile)
	}
	if err := tw.Flush(); err != nil {
		r.error(err)
		return 1
	}
	if found == 0 {
		_, _ = fmt.Fprintln(r.Out, "No local kits found")
	}
	return 0
}

func applyKit(path string, agent, image, profile *string, paths *[]string) error {
	doc, err := kit.Load(path)
	if err != nil {
		return err
	}
	if *agent != "" && doc.Spec.Agent != "" && *agent != doc.Spec.Agent {
		return fmt.Errorf("kit agent %q conflicts with requested agent %q", doc.Spec.Agent, *agent)
	}
	if *agent == "" {
		*agent = doc.Spec.Agent
	}
	if *image != "" && doc.Spec.Image != "" && *image != doc.Spec.Image {
		return fmt.Errorf("kit image %q conflicts with requested image %q", doc.Spec.Image, *image)
	}
	if *image == "" {
		*image = doc.Spec.Image
	}
	if *profile != "" && doc.Spec.PolicyProfile != "" && *profile != doc.Spec.PolicyProfile {
		return fmt.Errorf("kit policy profile %q conflicts with requested profile %q", doc.Spec.PolicyProfile, *profile)
	}
	if *profile == "" {
		*profile = doc.Spec.PolicyProfile
	}
	*paths = append(*paths, doc.Paths()...)
	return nil
}
