package command

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	sdk "github.com/KLORQ/sandboxes-go-sdk"
)

type ruleOutput struct {
	Protocol string `json:"protocol" yaml:"protocol"`
	CIDR     string `json:"cidr" yaml:"cidr"`
	Port     uint16 `json:"port" yaml:"port"`
}

func parseNetworkRule(value string) (sdk.NetworkRule, error) {
	protocol := tcpProtocol
	if strings.HasPrefix(value, "udp:") {
		protocol = udpProtocol
		value = strings.TrimPrefix(value, "udp:")
	}
	cidr := value
	port := uint16(0)
	if index := strings.LastIndexByte(value, ':'); index > 0 {
		parsed, err := strconv.ParseUint(value[index+1:], 10, 16)
		if err == nil {
			port = uint16(parsed)
			cidr = value[:index]
		}
	}
	ip, _, err := net.ParseCIDR(cidr)
	if err != nil || ip.To4() == nil {
		return sdk.NetworkRule{}, errors.New("network rule CIDR must be IPv4 (CIDR[:PORT], optional udp: prefix)")
	}
	return sdk.NetworkRule{Protocol: protocol, CIDR: cidr, Port: port}, nil
}

func resolveNetworkRules(values []string) ([]sdk.NetworkRule, error) {
	if len(values) > 64 {
		return nil, errors.New("at most 64 network rules are supported")
	}
	rules := make([]sdk.NetworkRule, 0, len(values))
	for _, value := range values {
		rule, err := parseNetworkRule(value)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", value, err)
		}
		rules = append(rules, rule)
	}
	return rules, nil
}

func rulesFor(sb *sdk.Sandbox) (allow, deny []ruleOutput) {
	convert := func(rules []sdk.NetworkRule) []ruleOutput {
		out := make([]ruleOutput, 0, len(rules))
		for i := range rules {
			out = append(out, ruleOutput{Protocol: rules[i].Protocol, CIDR: rules[i].CIDR, Port: rules[i].Port})
		}
		return out
	}
	return convert(sb.Allow), convert(sb.Deny)
}

func formatRules(rules []sdk.NetworkRule) string {
	if len(rules) == 0 {
		return "-"
	}
	parts := make([]string, 0, len(rules))
	for i := range rules {
		port := ""
		if rules[i].Port != 0 {
			port = fmt.Sprintf(":%d", rules[i].Port)
		}
		protocol := rules[i].Protocol
		if protocol == "" {
			protocol = tcpProtocol
		}
		parts = append(parts, fmt.Sprintf("%s:%s%s", protocol, rules[i].CIDR, port))
	}
	return strings.Join(parts, ", ")
}

func allowRules(sb *sdk.Sandbox) []ruleOutput {
	allow, _ := rulesFor(sb)
	return allow
}

func denyRules(sb *sdk.Sandbox) []ruleOutput {
	_, deny := rulesFor(sb)
	return deny
}
