package command

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"

	"gopkg.in/yaml.v3"

	"github.com/KLORQ/sandboxes-cli/internal/settings"
)

const settingsUsage = `Usage: ksbx settings COMMAND

View and manage local Klorq settings in ~/.config/klorq/settings.toml.

Commands:
  ls [--format table|json|yaml]   list settings and their effective source
  get KEY                         print one value
  set KEY VALUE                   set an override
  unset KEY                       remove an override

Keys:
  dns.upstream                    DNS upstream (host:port or https:// URL); restart required
  policy.profile                  default policy profile: deny-all, balanced, sbx-compat
  defaults.cpus                   CPU count for new sandboxes (0 = host-derived)
  defaults.memory_mib             memory in MiB for new sandboxes (0 = host-derived)
  sandbox.disk.dockerVolume       ext4 Docker volume size such as 10g (minimum 512m)
`

type settingOutput struct {
	Key         string `json:"key" yaml:"key"`
	Value       string `json:"value" yaml:"value"`
	Type        string `json:"type" yaml:"type"`
	Source      string `json:"source" yaml:"source"`
	Restart     bool   `json:"restart" yaml:"restart"`
	Description string `json:"description" yaml:"description"`
}

func (r *Runner) settings(args []string) int {
	if len(args) == 0 {
		_, _ = fmt.Fprint(r.Err, settingsUsage)
		return 2
	}
	switch args[0] {
	case helpCommand, helpShort, helpFlag:
		_, _ = fmt.Fprint(r.Out, settingsUsage)
		return 0
	case "ls", commandList:
		return r.settingsList(args[1:])
	case commandGet:
		return r.settingsGet(args[1:])
	case commandSet:
		return r.settingsSet(args[1:])
	case "unset":
		return r.settingsUnset(args[1:])
	default:
		_, _ = fmt.Fprintf(r.Err, "ksbx settings: unknown subcommand %q\n", args[0])
		_, _ = fmt.Fprint(r.Err, settingsUsage)
		return 2
	}
}

func (r *Runner) settingsPath() string {
	if path := strings.TrimSpace(os.Getenv("KLORQ_SETTINGS_FILE")); path != "" {
		return path
	}
	return settings.DefaultPath()
}

func (r *Runner) settingsList(args []string) int {
	fs := flag.NewFlagSet("settings ls", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	format := fs.String("format", listFormatTable, "output format: table, json or yaml")
	jsonOutput := fs.Bool("json", false, "output in JSON format")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return r.flagParseFailure("settings ls", err)
	}
	if fs.NArg() != 0 {
		_, _ = fmt.Fprintln(r.Err, "usage: ksbx settings ls [--format table|json|yaml]")
		return 2
	}
	selected, err := resolveOperationFormat(*format, *jsonOutput)
	if err != nil {
		r.error(err)
		return 2
	}
	values, err := settings.Load(r.settingsPath())
	if err != nil {
		r.error(err)
		return 1
	}
	rows := settingRows(values)
	switch selected {
	case listFormatTable:
		tw := tabwriter.NewWriter(r.Out, 0, 4, 2, ' ', 0)
		_, _ = fmt.Fprintln(tw, "KEY\tVALUE\tTYPE\tSOURCE\tRESTART\tDESCRIPTION")
		for _, row := range rows {
			_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", row.Key, row.Value, row.Type, row.Source, boolMarker(row.Restart), row.Description)
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

func boolMarker(value bool) string {
	if value {
		return "yes"
	}
	return ""
}

func settingRows(values settings.Values) []settingOutput {
	return []settingOutput{
		settingRow("dns.upstream", values.DNSUpstream, values.DNSUpstream != "", "string", true, "DNS upstream used by sandbox gateways"),
		settingRow("policy.profile", values.DefaultPolicyProfile, values.DefaultPolicyProfile != "", "string", false, "Default network policy profile for new sandboxes"),
		settingRow("defaults.cpus", uintString(values.DefaultCPUs), values.DefaultCPUs != 0, "int", false, "CPU count for new sandboxes (0 = host-derived)"),
		settingRow("defaults.memory_mib", uintString(values.DefaultMemoryMiB), values.DefaultMemoryMiB != 0, "int", false, "Memory in MiB for new sandboxes (0 = host-derived)"),
		settingRow("sandbox.disk.dockerVolume", values.DockerVolumeSize, values.DockerVolumeSize != "", "string", false, "ext4 Docker volume size for new sandboxes"),
	}
}

func settingRow(key, value string, set bool, kind string, restart bool, description string) settingOutput {
	source := "default"
	if set {
		source = "file"
	} else {
		value = ""
	}
	return settingOutput{Key: key, Value: value, Type: kind, Source: source, Restart: restart, Description: description}
}

func uintString(value uint32) string {
	if value == 0 {
		return ""
	}
	return strconv.FormatUint(uint64(value), 10)
}

func (r *Runner) settingsGet(args []string) int {
	if len(args) != 1 {
		_, _ = fmt.Fprintln(r.Err, "usage: ksbx settings get KEY")
		return 2
	}
	values, err := settings.Load(r.settingsPath())
	if err != nil {
		r.error(err)
		return 1
	}
	row, found := findSettingRow(settingRows(values), args[0])
	if !found {
		r.error(fmt.Errorf("unknown setting %q", args[0]))
		return 2
	}
	_, _ = fmt.Fprintln(r.Out, row.Value)
	return 0
}

func (r *Runner) settingsSet(args []string) int {
	if len(args) != 2 {
		_, _ = fmt.Fprintln(r.Err, "usage: ksbx settings set KEY VALUE")
		return 2
	}
	values, err := settings.Load(r.settingsPath())
	if err != nil {
		r.error(err)
		return 1
	}
	if err := applySetting(&values, args[0], args[1]); err != nil {
		r.error(err)
		return 2
	}
	if err := settings.Save(r.settingsPath(), values); err != nil {
		r.error(err)
		return 1
	}
	_, _ = fmt.Fprintf(r.Out, "set %s\n", args[0])
	if restart := settingRestart(args[0]); restart {
		_, _ = fmt.Fprintf(r.Out, "restart klorqd to apply %s\n", args[0])
	}
	return 0
}

func (r *Runner) settingsUnset(args []string) int {
	if len(args) != 1 {
		_, _ = fmt.Fprintln(r.Err, "usage: ksbx settings unset KEY")
		return 2
	}
	values, err := settings.Load(r.settingsPath())
	if err != nil {
		r.error(err)
		return 1
	}
	if err := applySetting(&values, args[0], ""); err != nil {
		r.error(err)
		return 2
	}
	if err := settings.Save(r.settingsPath(), values); err != nil {
		r.error(err)
		return 1
	}
	_, _ = fmt.Fprintf(r.Out, "unset %s\n", args[0])
	return 0
}

func settingRestart(key string) bool {
	return key == "dns.upstream"
}

func findSettingRow(rows []settingOutput, key string) (settingOutput, bool) {
	for _, row := range rows {
		if row.Key == key {
			return row, true
		}
	}
	return settingOutput{}, false
}

func applySetting(values *settings.Values, key, value string) error {
	switch key {
	case "dns.upstream":
		value = strings.TrimSpace(value)
		if err := validateDNSUpstream(value); err != nil {
			return err
		}
		values.DNSUpstream = value
	case "policy.profile":
		switch value {
		case "", "deny-all", "balanced", "sbx-compat":
			values.DefaultPolicyProfile = value
		default:
			return errors.New("policy.profile must be deny-all, balanced or sbx-compat")
		}
	case "defaults.cpus":
		parsed, err := parseSettingUint(value, 0, 64)
		if err != nil {
			return fmt.Errorf("defaults.cpus: %w", err)
		}
		values.DefaultCPUs = uint32(parsed) //nolint:gosec // parseSettingUint bounds the value to 64.
	case "defaults.memory_mib":
		parsed, err := parseSettingUint(value, 0, 32768)
		if err != nil {
			return fmt.Errorf("defaults.memory_mib: %w", err)
		}
		values.DefaultMemoryMiB = uint32(parsed) //nolint:gosec // parseSettingUint bounds the value to 32768.
	case "sandbox.disk.dockerVolume":
		if value != "" && !validVolumeSize(value) {
			return errors.New("sandbox.disk.dockerVolume must be a size such as 10g or 512m (minimum 512 MiB)")
		}
		values.DockerVolumeSize = value
	default:
		return fmt.Errorf("unknown setting %q", key)
	}
	return nil
}

func parseSettingUint(value string, minValue, maxValue uint64) (uint64, error) {
	if value == "" {
		return 0, nil
	}
	parsed, err := strconv.ParseUint(value, 10, 32)
	if err != nil || parsed < minValue || parsed > maxValue {
		return 0, fmt.Errorf("must be an integer between %d and %d", minValue, maxValue)
	}
	return parsed, nil
}

func validateDNSUpstream(value string) error {
	if value == "" {
		return nil
	}
	if strings.HasPrefix(value, "https://") || strings.HasPrefix(value, "http://") {
		return errors.New("DNS-over-HTTPS is not implemented; use a UDP HOST:PORT resolver")
	}
	host, port, err := net.SplitHostPort(value)
	if err != nil {
		return errors.New("dns.upstream must be HOST:PORT")
	}
	if host == "" || net.ParseIP(host) == nil && !validDNSHost(host) {
		return errors.New("dns.upstream has an invalid host")
	}
	parsed, err := strconv.ParseUint(port, 10, 16)
	if err != nil || parsed == 0 {
		return errors.New("dns.upstream port must be 1..65535")
	}
	return nil
}

func validDNSHost(host string) bool {
	if host == "" || len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		for _, r := range label {
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' {
				continue
			}
			return false
		}
	}
	return true
}

func validVolumeSize(value string) bool {
	if len(value) < 2 {
		return false
	}
	unit := value[len(value)-1]
	if unit != 'm' && unit != 'g' {
		return false
	}
	number, err := strconv.ParseUint(value[:len(value)-1], 10, 32)
	if err != nil {
		return false
	}
	bytes := number
	if unit == 'g' {
		bytes *= 1024
	}
	return bytes >= 512
}
