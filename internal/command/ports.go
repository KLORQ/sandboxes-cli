package command

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"text/tabwriter"

	"gopkg.in/yaml.v3"

	sdk "github.com/KLORQ/sandboxes-go-sdk"
)

const (
	tcpProtocol = "tcp"
	udpProtocol = "udp"
)

type portOutput struct {
	Host     uint16 `json:"host" yaml:"host"`
	Guest    uint16 `json:"guest" yaml:"guest"`
	Protocol string `json:"protocol" yaml:"protocol"`
}

func parsePublishSpec(value string) (sdk.Port, error) {
	return parsePortSpec(value, true)
}

func parsePortSpec(value string, allocateHost bool) (sdk.Port, error) {
	protocol := tcpProtocol
	if before, after, found := strings.Cut(value, "/"); found {
		value = before
		protocol = after
	}
	if protocol != tcpProtocol && protocol != udpProtocol {
		return sdk.Port{}, errors.New("port protocol must be tcp or udp")
	}
	parts := strings.Split(value, ":")
	if len(parts) == 1 {
		return ephemeralPort(parts[0], protocol, allocateHost)
	}
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return sdk.Port{}, errors.New("port spec must be HOST:GUEST[/tcp] or GUEST[/tcp]")
	}
	host, err := strconv.ParseUint(parts[0], 10, 16)
	if err != nil || host == 0 {
		return sdk.Port{}, errors.New("host port must be 1..65535")
	}
	guest, err := strconv.ParseUint(parts[1], 10, 16)
	if err != nil || guest == 0 {
		return sdk.Port{}, errors.New("guest port must be 1..65535")
	}
	return sdk.Port{Host: uint16(host), Guest: uint16(guest), Protocol: protocol}, nil
}

func ephemeralPort(value, protocol string, allocateHost bool) (sdk.Port, error) {
	if !allocateHost {
		return sdk.Port{}, errors.New("unpublish must be HOST:GUEST[/tcp]")
	}
	guest, err := strconv.ParseUint(value, 10, 16)
	if err != nil || guest == 0 {
		return sdk.Port{}, errors.New("guest port must be 1..65535")
	}
	host, err := allocateHostPort()
	if err != nil {
		return sdk.Port{}, err
	}
	return sdk.Port{Host: host, Guest: uint16(guest), Protocol: protocol}, nil
}

func allocateHostPort() (uint16, error) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return 0, fmt.Errorf("allocate host port: %w", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		return 0, fmt.Errorf("release allocated host port: %w", err)
	}
	if port <= 0 || port > 65535 {
		return 0, errors.New("allocated host port is out of range")
	}
	return uint16(port), nil
}

func resolvePorts(values []string) ([]sdk.Port, error) {
	return resolvePortSpecs(values, true)
}

func resolvePortSpecs(values []string, allocateHost bool) ([]sdk.Port, error) {
	if len(values) > 32 {
		return nil, errors.New("at most 32 published ports are supported")
	}
	ports := make([]sdk.Port, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		port, err := parsePortSpec(value, allocateHost)
		if err != nil {
			return nil, err
		}
		key := port.Protocol + ":" + strconv.Itoa(int(port.Host))
		if _, exists := seen[key]; exists {
			return nil, fmt.Errorf("duplicate host port %d/%s", port.Host, port.Protocol)
		}
		seen[key] = struct{}{}
		ports = append(ports, port)
	}
	return ports, nil
}

func portsFor(sb *sdk.Sandbox) []portOutput {
	out := make([]portOutput, 0, len(sb.Ports))
	for i := range sb.Ports {
		out = append(out, portOutput{Host: sb.Ports[i].Host, Guest: sb.Ports[i].Guest, Protocol: sb.Ports[i].Protocol})
	}
	return out
}

func (r *Runner) ports(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("ports", flag.ContinueOnError)
	fs.SetOutput(r.Err)
	format := fs.String("format", listFormatTable, "output format: table, json or yaml")
	jsonOutput := fs.Bool("json", false, "output in JSON format")
	var publishFlags, unpublishFlags stringListFlag
	fs.Var(&publishFlags, "publish", "publish HOST:GUEST[/tcp] (repeatable)")
	fs.Var(&unpublishFlags, "unpublish", "unpublish HOST:GUEST[/tcp] (repeatable)")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() != 1 {
		_, _ = fmt.Fprintln(r.Err, "usage: ksbx ports [--publish HOST:GUEST] [--unpublish HOST:GUEST] [--format table|json|yaml] SANDBOX")
		return 2
	}
	if len(publishFlags) > 0 || len(unpublishFlags) > 0 {
		return r.portsMutate(ctx, fs.Arg(0), publishFlags, unpublishFlags)
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
	id, err := findExecSandbox(ctx, client, fs.Arg(0))
	if err != nil {
		r.error(err)
		return 1
	}
	sb, err := client.Sandboxes().Get(ctx, id)
	if err != nil {
		r.error(err)
		return 1
	}
	if err := renderPortList(r.Out, selected, portsFor(sb)); err != nil {
		r.error(err)
		return 1
	}
	return 0
}

func (r *Runner) portsMutate(ctx context.Context, sandbox string, publishFlags, unpublishFlags []string) int {
	published, err := resolvePorts(publishFlags)
	if err != nil {
		r.error(err)
		return 2
	}
	unpublished, err := resolvePortSpecs(unpublishFlags, false)
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
	id, err := findExecSandbox(ctx, client, sandbox)
	if err != nil {
		r.error(err)
		return 1
	}
	sb, err := client.Sandboxes().Get(ctx, id)
	if err != nil {
		r.error(err)
		return 1
	}
	ports, err := applyPortChanges(sb.Ports, published, unpublished)
	if err != nil {
		r.error(err)
		return 1
	}
	updated, err := sdk.Ports(client).UpdatePorts(ctx, id, ports)
	if err != nil {
		r.error(err)
		return 1
	}
	_, _ = fmt.Fprintf(r.Out, "updated ports for %s (%d)\n", updated.Name, len(updated.Ports))
	return 0
}

func applyPortChanges(existing, published, unpublished []sdk.Port) ([]sdk.Port, error) {
	ports := append([]sdk.Port(nil), existing...)
	for i := range published {
		for j := range ports {
			if ports[j].Host == published[i].Host && ports[j].Protocol == published[i].Protocol {
				return nil, fmt.Errorf("host port %d/%s is already published", published[i].Host, published[i].Protocol)
			}
		}
		ports = append(ports, published[i])
	}
	for i := range unpublished {
		removed := false
		for j := range ports {
			if ports[j].Host == unpublished[i].Host && ports[j].Guest == unpublished[i].Guest && ports[j].Protocol == unpublished[i].Protocol {
				ports = append(ports[:j], ports[j+1:]...)
				removed = true
				break
			}
		}
		if !removed {
			return nil, fmt.Errorf("port %d:%d is not published", unpublished[i].Host, unpublished[i].Guest)
		}
	}
	return ports, nil
}

func renderPortList(out io.Writer, format string, ports []portOutput) error {
	switch format {
	case listFormatTable:
		if len(ports) == 0 {
			_, err := fmt.Fprintln(out, "No published ports")
			return err
		}
		return writePortTable(out, ports)
	case listFormatYAML:
		data, err := yaml.Marshal(ports)
		if err != nil {
			return err
		}
		_, err = out.Write(data)
		return err
	default:
		encoder := json.NewEncoder(out)
		encoder.SetIndent("", "  ")
		return encoder.Encode(ports)
	}
}

func writePortTable(out io.Writer, ports []portOutput) error {
	tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "HOST\tGUEST\tPROTOCOL")
	for _, port := range ports {
		_, _ = fmt.Fprintf(tw, "%d\t%d\t%s\n", port.Host, port.Guest, port.Protocol)
	}
	return tw.Flush()
}
