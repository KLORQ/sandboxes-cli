package command

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"gopkg.in/yaml.v3"
)

const templateUsage = `Usage: ksbx template COMMAND

Commands:
  ls [--format table|json|yaml]   list built-in agent template images
  inspect NAME [--json]            show the pinned image and status

save/load/rm are not implemented: this build does not snapshot or import
sandbox images. Use --image or a local kit for a custom image.
`

type templateOutput struct {
	Name    string `json:"name" yaml:"name"`
	Image   string `json:"image,omitempty" yaml:"image,omitempty"`
	Command string `json:"command,omitempty" yaml:"command,omitempty"`
	Status  string `json:"status" yaml:"status"`
	Docker  bool   `json:"docker,omitempty" yaml:"docker,omitempty"`
	Notes   string `json:"notes,omitempty" yaml:"notes,omitempty"`
}

func (r *Runner) template(args []string) int {
	if len(args) == 0 {
		_, _ = fmt.Fprint(r.Err, templateUsage)
		return 2
	}
	switch args[0] {
	case helpCommand, helpShort, helpFlag:
		_, _ = fmt.Fprint(r.Out, templateUsage)
		return 0
	case "ls", commandList:
		return r.templateList(args[1:])
	case commandInspect:
		return r.templateInspect(args[1:])
	case "save", "load", "rm":
		_, _ = fmt.Fprintf(r.Err, "ksbx template %s: unsupported: local template snapshots/import/removal are not implemented\n", args[0])
		return 1
	default:
		_, _ = fmt.Fprintf(r.Err, "ksbx template: unknown subcommand %q\n", args[0])
		return 2
	}
}

func (r *Runner) templateList(args []string) int {
	fs := flag.NewFlagSet("template ls", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	format := fs.String("format", listFormatTable, "output format: table, json or yaml")
	jsonOutput := fs.Bool("json", false, "output in JSON format")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return r.flagParseFailure("template ls", err)
	}
	if fs.NArg() != 0 {
		_, _ = fmt.Fprint(r.Err, templateUsage)
		return 2
	}
	selected, err := resolveOperationFormat(*format, *jsonOutput)
	if err != nil {
		r.error(err)
		return 2
	}
	rows, err := templateRows()
	if err != nil {
		r.error(err)
		return 1
	}
	switch selected {
	case listFormatTable:
		tw := tabwriter.NewWriter(r.Out, 0, 4, 2, ' ', 0)
		_, _ = fmt.Fprintln(tw, "NAME\tIMAGE\tSTATUS\tDOCKER")
		for _, row := range rows {
			_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%t\n", row.Name, row.Image, row.Status, row.Docker)
		}
		if err := tw.Flush(); err != nil {
			r.error(err)
			return 1
		}
		return 0
	case listFormatYAML:
		data, err := yaml.Marshal(rows)
		if err != nil {
			r.error(err)
			return 1
		}
		_, _ = r.Out.Write(data)
		return 0
	default:
		encoder := json.NewEncoder(r.Out)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(rows); err != nil {
			r.error(err)
			return 1
		}
		return 0
	}
}

func (r *Runner) templateInspect(args []string) int {
	fs := flag.NewFlagSet("template inspect", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jsonOutput := fs.Bool("json", false, "output in JSON format")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return r.flagParseFailure("template inspect", err)
	}
	if fs.NArg() != 1 {
		_, _ = fmt.Fprint(r.Err, "usage: ksbx template inspect NAME [--json]\n")
		return 2
	}
	rows, err := templateRows()
	if err != nil {
		r.error(err)
		return 1
	}
	for _, row := range rows {
		if row.Name != fs.Arg(0) {
			continue
		}
		if *jsonOutput {
			encoder := json.NewEncoder(r.Out)
			encoder.SetIndent("", "  ")
			if err := encoder.Encode(row); err != nil {
				r.error(err)
				return 1
			}
			return 0
		}
		_, _ = fmt.Fprintf(r.Out, "name: %s\nimage: %s\ncommand: %s\nstatus: %s\ndocker: %t\nnotes: %s\n", row.Name, row.Image, row.Command, row.Status, row.Docker, row.Notes)
		return 0
	}
	r.error(fmt.Errorf("unknown template %q", fs.Arg(0)))
	return 1
}

func templateRows() ([]templateOutput, error) {
	registry, err := agentRegistry()
	if err != nil {
		return nil, err
	}
	out := make([]templateOutput, 0, len(registry.Names()))
	for _, name := range registry.Names() {
		spec, _ := registry.Lookup(name)
		out = append(out, templateOutput{
			Name: name, Image: spec.Image, Command: strings.Join(spec.Command, " "),
			Status: string(spec.Status), Docker: spec.Docker, Notes: spec.Notes,
		})
	}
	return out, nil
}
