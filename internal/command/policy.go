package command

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"text/tabwriter"

	"gopkg.in/yaml.v3"

	sdk "github.com/KLORQ/sandboxes-go-sdk"
)

type policyRuleOutput struct {
	Action   string `json:"action" yaml:"action"`
	Protocol string `json:"protocol" yaml:"protocol"`
	CIDR     string `json:"cidr" yaml:"cidr"`
	Port     uint16 `json:"port" yaml:"port"`
}

func (r *Runner) policy(ctx context.Context, args []string) int {
	if len(args) == 0 {
		_, _ = fmt.Fprint(r.Err, policyUsage)
		return 2
	}
	switch args[0] {
	case "ls", "inspect":
		return r.policyList(ctx, args[1:])
	case "check":
		if len(args) > 1 && args[1] == networkKeyword {
			return r.policyCheckNetwork(ctx, args[2:])
		}
		return r.policyCheck(ctx, args[1:])
	case "allow", "deny", "rm":
		if len(args) > 1 && args[1] == networkKeyword {
			return r.policyMutateNetwork(ctx, args[0], args[2:])
		}
		return r.policyMutate(ctx, args[0], args[1:])
	case "reset", "init", "refresh", "log", "approval", "profile":
		_, _ = fmt.Fprintf(r.Err, "ksbx policy %s: this policy operation is not implemented\n", args[0])
		return 1
	case helpCommand, helpShort, helpFlag:
		_, _ = fmt.Fprint(r.Out, policyUsage)
		return 0
	default:
		_, _ = fmt.Fprintf(r.Err, "ksbx policy: unknown subcommand %q\n", args[0])
		_, _ = fmt.Fprint(r.Err, policyUsage)
		return 2
	}
}

// policyNetworkScope parses the shared `policy <verb> network [--sandbox NAME]`
// grammar used by the Docker sbx baseline. An empty sandbox name means the
// global scope, which the local runtime does not implement.
func (r *Runner) policyNetworkScope(cmdPath string, args []string) (sandboxName string, rest []string, code int) {
	fs := flag.NewFlagSet(cmdPath, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&sandboxName, "sandbox", "", "scope the rule to one sandbox (global scope is not implemented locally)")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return "", nil, 0
		}
		return "", nil, r.flagParseFailure(cmdPath, err)
	}
	return sandboxName, fs.Args(), -1
}

func (r *Runner) policyMutateNetwork(ctx context.Context, action string, args []string) int {
	sandboxName, rest, code := r.policyNetworkScope("policy "+action+" network", args)
	if code >= 0 {
		return code
	}
	if sandboxName == "" {
		_, _ = fmt.Fprintln(r.Err, "error: global policy rules are not implemented by the local runtime; use --sandbox NAME")
		return 1
	}
	if len(rest) != 1 {
		_, _ = fmt.Fprintf(r.Err, "usage: ksbx policy %s network --sandbox NAME CIDR[:PORT]\n", action)
		return 2
	}
	return r.policyMutate(ctx, action, []string{sandboxName, rest[0]})
}

func (r *Runner) policyCheckNetwork(ctx context.Context, args []string) int {
	sandboxName, rest, code := r.policyNetworkScope("policy check network", args)
	if code >= 0 {
		return code
	}
	if len(rest) != 1 {
		_, _ = fmt.Fprintln(r.Err, "usage: ksbx policy check network [--sandbox NAME] TARGET (IPv4[:PORT], IPv6[:PORT], or http(s)://URL)")
		return 2
	}
	host, port, err := parsePolicyTarget(rest[0])
	if err != nil {
		r.error(err)
		return 2
	}
	if host == nil {
		r.error(fmt.Errorf("unsupported policy target %q: domain and wildcard rules are not implemented by the local runtime policy model", rest[0]))
		return 2
	}
	client, err := r.client()
	if err != nil {
		r.error(err)
		return 1
	}
	defer func() { _ = client.Close() }()
	var allow, deny []sdk.NetworkRule
	if sandboxName != "" {
		id, err := findExecSandbox(ctx, client, sandboxName)
		if err != nil {
			r.error(err)
			return 1
		}
		sb, err := client.Sandboxes().Get(ctx, id)
		if err != nil {
			r.error(err)
			return 1
		}
		allow, deny = sb.Allow, sb.Deny
	}
	if host.To4() == nil {
		r.error(errors.New("IPv6 policy targets are not implemented by the local runtime policy model"))
		return 2
	}
	allowed, reason := evaluatePolicyTarget(allow, deny, tcpProtocol, host, port)
	if allowed {
		_, _ = fmt.Fprintf(r.Out, "allowed: %s\n", reason)
		return 0
	}
	_, _ = fmt.Fprintf(r.Out, "denied: %s\n", reason)
	return 1
}

// parsePolicyTarget extracts a host and optional port from an IPv4/IPv6
// literal or an http(s) URL. A zero port means "any port".
func parsePolicyTarget(target string) (net.IP, uint16, error) {
	if strings.Contains(target, "://") {
		return parseURLPolicyTarget(target)
	}
	if host, portText, err := net.SplitHostPort(target); err == nil {
		port, err := strconv.ParseUint(portText, 10, 16)
		if err != nil || port == 0 {
			return nil, 0, errors.New("port must be 1..65535")
		}
		return net.ParseIP(host), uint16(port), nil
	}
	if strings.Count(target, ":") >= 1 && net.ParseIP(target) == nil {
		return nil, 0, fmt.Errorf("unsupported policy target %q; use IPv4[:PORT], IPv6[:PORT], or an http(s) URL", target)
	}
	return net.ParseIP(target), 0, nil
}

func parseURLPolicyTarget(target string) (net.IP, uint16, error) {
	parsed, err := url.Parse(target)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return nil, 0, fmt.Errorf("unsupported policy target %q; use IPv4/IPv6 or an http(s) URL", target)
	}
	host := parsed.Hostname()
	if parsed.Port() != "" {
		port, err := strconv.ParseUint(parsed.Port(), 10, 16)
		if err != nil || port == 0 {
			return nil, 0, errors.New("URL port must be 1..65535")
		}
		return net.ParseIP(host), uint16(port), nil
	}
	if parsed.Scheme == "https" {
		return net.ParseIP(host), 443, nil
	}
	return net.ParseIP(host), 80, nil
}

// evaluatePolicyTarget evaluates rules for a host; a zero port matches rules
// for any port (deny still wins over a narrower allow).
func evaluatePolicyTarget(allow, deny []sdk.NetworkRule, protocol string, ip net.IP, port uint16) (bool, string) {
	if port != 0 {
		return evaluatePolicy(allow, deny, protocol, ip, port)
	}
	matches := func(rules []sdk.NetworkRule) string {
		for i := range rules {
			rule := rules[i]
			ruleProtocol := rule.Protocol
			if ruleProtocol == "" {
				ruleProtocol = tcpProtocol
			}
			if ruleProtocol != protocol {
				continue
			}
			_, network, err := net.ParseCIDR(rule.CIDR)
			if err != nil || !network.Contains(ip) {
				continue
			}
			return rule.CIDR
		}
		return ""
	}
	if cidr := matches(deny); cidr != "" {
		return false, "deny rule " + cidr
	}
	if cidr := matches(allow); cidr != "" {
		return true, "allow rule " + cidr
	}
	return false, "default deny"
}

func (r *Runner) policyList(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("policy ls", flag.ContinueOnError)
	fs.SetOutput(r.Err)
	format := fs.String("format", listFormatTable, "output format: table, json or yaml")
	jsonOutput := fs.Bool("json", false, "output in JSON format")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return r.flagParseFailure("policy ls", err)
	}
	if fs.NArg() != 1 {
		_, _ = fmt.Fprintln(r.Err, "usage: ksbx policy ls [--format table|json|yaml] SANDBOX")
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
	rules := policyRules(sb)
	if err := renderPolicyRules(r.Out, selected, rules); err != nil {
		r.error(err)
		return 1
	}
	return 0
}

func (r *Runner) policyMutate(ctx context.Context, action string, args []string) int {
	if len(args) != 2 {
		_, _ = fmt.Fprintf(r.Err, "usage: ksbx policy %s SANDBOX CIDR[:PORT]\n", action)
		return 2
	}
	rule, err := parseNetworkRule(args[1])
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
	id, err := findExecSandbox(ctx, client, args[0])
	if err != nil {
		r.error(err)
		return 1
	}
	updated, err := sdk.Policies(client).MutatePolicy(ctx, id, action, rule)
	if err != nil {
		r.error(err)
		return 1
	}
	_, _ = fmt.Fprintf(r.Out, "updated policy for %s (allow=%d deny=%d)\n", updated.Name, len(updated.Allow), len(updated.Deny))
	return 0
}

func (r *Runner) policyCheck(ctx context.Context, args []string) int {
	if len(args) != 3 && len(args) != 4 {
		_, _ = fmt.Fprintln(r.Err, "usage: ksbx policy check SANDBOX CIDR PORT [PROTOCOL]")
		return 2
	}
	protocol := tcpProtocol
	if len(args) == 4 {
		protocol = strings.ToLower(args[3])
	}
	if protocol != tcpProtocol && protocol != udpProtocol {
		r.error(errors.New("protocol must be tcp or udp"))
		return 2
	}
	ip, err := parsePolicyDestination(args[1])
	if err != nil {
		r.error(err)
		return 2
	}
	port, err := strconv.ParseUint(args[2], 10, 16)
	if err != nil || port == 0 {
		r.error(errors.New("port must be 1..65535"))
		return 2
	}
	client, err := r.client()
	if err != nil {
		r.error(err)
		return 1
	}
	defer func() { _ = client.Close() }()
	id, err := findExecSandbox(ctx, client, args[0])
	if err != nil {
		r.error(err)
		return 1
	}
	sb, err := client.Sandboxes().Get(ctx, id)
	if err != nil {
		r.error(err)
		return 1
	}
	allowed, reason := evaluatePolicy(sb.Allow, sb.Deny, protocol, ip, uint16(port))
	if allowed {
		_, _ = fmt.Fprintf(r.Out, "allowed: %s\n", reason)
		return 0
	}
	_, _ = fmt.Fprintf(r.Out, "denied: %s\n", reason)
	return 1
}

func parsePolicyDestination(value string) (net.IP, error) {
	ip := net.ParseIP(value)
	if ip == nil || ip.To4() == nil {
		return nil, errors.New("destination must be a single IPv4 address")
	}
	return ip.To4(), nil
}

func policyRules(sb *sdk.Sandbox) []policyRuleOutput {
	out := make([]policyRuleOutput, 0, len(sb.Allow)+len(sb.Deny))
	appendRules := func(action string, rules []sdk.NetworkRule) {
		for i := range rules {
			protocol := rules[i].Protocol
			if protocol == "" {
				protocol = tcpProtocol
			}
			out = append(out, policyRuleOutput{Action: action, Protocol: protocol, CIDR: rules[i].CIDR, Port: rules[i].Port})
		}
	}
	appendRules("allow", sb.Allow)
	appendRules("deny", sb.Deny)
	return out
}

func renderPolicyRules(out io.Writer, format string, rules []policyRuleOutput) error {
	switch format {
	case listFormatTable:
		if len(rules) == 0 {
			_, err := fmt.Fprintln(out, "No policy rules (default deny)")
			return err
		}
		_, _ = fmt.Fprintln(out, "NETWORK")
		tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
		_, _ = fmt.Fprintln(tw, "ACTION\tPROTOCOL\tCIDR\tPORT")
		for _, rule := range rules {
			_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%d\n", rule.Action, rule.Protocol, rule.CIDR, rule.Port)
		}
		return tw.Flush()
	case listFormatYAML:
		data, err := yaml.Marshal(rules)
		if err != nil {
			return err
		}
		_, err = out.Write(data)
		return err
	default:
		encoder := json.NewEncoder(out)
		encoder.SetIndent("", "  ")
		return encoder.Encode(rules)
	}
}

func evaluatePolicy(allow, deny []sdk.NetworkRule, protocol string, ip net.IP, port uint16) (bool, string) {
	matches := func(rules []sdk.NetworkRule) string {
		for i := range rules {
			rule := rules[i]
			ruleProtocol := rule.Protocol
			if ruleProtocol == "" {
				ruleProtocol = tcpProtocol
			}
			if ruleProtocol != protocol {
				continue
			}
			if rule.Port != 0 && rule.Port != port {
				continue
			}
			_, network, err := net.ParseCIDR(rule.CIDR)
			if err != nil || !network.Contains(ip) {
				continue
			}
			return rule.CIDR
		}
		return ""
	}
	if cidr := matches(deny); cidr != "" {
		return false, "deny rule " + cidr
	}
	if cidr := matches(allow); cidr != "" {
		return true, "allow rule " + cidr
	}
	return false, "default deny"
}

const policyUsage = `Usage: ksbx policy COMMAND

Commands:
  ls SANDBOX [--format table|json|yaml]       list stored allow/deny rules
  inspect SANDBOX                             alias for ls
  allow|deny|rm SANDBOX CIDR[:PORT]           change per-sandbox rules
  allow|deny|rm network --sandbox NAME CIDR[:PORT]
                                              Docker sbx grammar for per-sandbox rules
  check SANDBOX IP PORT [PROTOCOL]            evaluate a request against stored rules
  check network [--sandbox NAME] TARGET       Docker sbx grammar; TARGET is
                                              IPv4[:PORT], IPv6[:PORT], or http(s)://URL

Global (sandbox-less) rules, domain/wildcard rules, and filesystem policy are
not implemented by the local runtime; the default is deny.
`
