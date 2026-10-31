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
		return r.policyCheck(ctx, args[1:])
	case "allow", "deny", "rm":
		return r.policyMutate(ctx, args[0], args[1:])
	case "init":
		return r.policyInit(ctx, args[1:])
	case "profile":
		return r.policyProfile(ctx, args[1:])
	case "reset", "refresh", "log", "approval":
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

func (r *Runner) policyList(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("policy ls", flag.ContinueOnError)
	fs.SetOutput(r.Err)
	format := fs.String("format", listFormatTable, "output format: table, json or yaml")
	jsonOutput := fs.Bool("json", false, "output in JSON format")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
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

func (r *Runner) policyInit(ctx context.Context, args []string) int {
	if len(args) != 1 {
		_, _ = fmt.Fprintln(r.Err, "usage: ksbx policy init allow-all|balanced|deny-all")
		return 2
	}
	profile := args[0]
	if profile != "allow-all" && profile != "balanced" && profile != "deny-all" {
		_, _ = fmt.Fprintln(r.Err, "profile must be allow-all, balanced or deny-all")
		return 2
	}
	client, err := r.client()
	if err != nil {
		r.error(err)
		return 1
	}
	defer func() { _ = client.Close() }()
	applied, err := sdk.Policies(client).SetPolicyProfile(ctx, profile)
	if err != nil {
		r.error(err)
		return 1
	}
	_, _ = fmt.Fprintf(r.Out, "global policy profile: %s\n", applied)
	return 0
}

func (r *Runner) policyProfile(ctx context.Context, args []string) int {
	if len(args) > 1 || (len(args) == 1 && args[0] != "ls" && args[0] != "list") {
		_, _ = fmt.Fprintln(r.Err, "usage: ksbx policy profile [ls]")
		return 2
	}
	client, err := r.client()
	if err != nil {
		r.error(err)
		return 1
	}
	defer func() { _ = client.Close() }()
	profile, err := sdk.Policies(client).GetPolicyProfile(ctx)
	if err != nil {
		r.error(err)
		return 1
	}
	_, _ = fmt.Fprintf(r.Out, "global: %s\navailable: deny-all, balanced, allow-all\n", profile)
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
  ls SANDBOX [--format table|json|yaml]   list stored allow/deny rules
  inspect SANDBOX                         alias for ls
  allow SANDBOX CIDR[:PORT]               add an allow rule (live for running sandboxes)
  deny SANDBOX CIDR[:PORT]                add a deny rule (live for running sandboxes)
  rm SANDBOX CIDR[:PORT]                  remove an allow or deny rule
  check SANDBOX IP PORT [PROTOCOL]        evaluate a request against stored rules
  init allow-all|balanced|deny-all        set the global default profile
  profile [ls]                            show the global default and available profiles

reset/refresh/log/approvals and filesystem/domain rules are not implemented.
Default is deny-all.
`
