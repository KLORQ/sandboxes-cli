package command

import (
	"fmt"

	sdk "github.com/KLORQ/sandboxes-go-sdk"
)

const (
	anyIPv4CIDR           = "0.0.0.0/0"
	policyProfileDenyAll  = "deny-all"
	policyProfileBalanced = "balanced"
	policyProfileCompat   = "sbx-compat"
)

// profileRules returns the built-in egress allowlist for an opt-in policy
// profile. The default remains deny-all; profiles never weaken the default
// unless the caller explicitly selects one.
func profileRules(profile string) ([]sdk.NetworkRule, error) {
	switch profile {
	case "", policyProfileDenyAll:
		return nil, nil
	case policyProfileBalanced:
		return []sdk.NetworkRule{
			{Protocol: tcpProtocol, CIDR: anyIPv4CIDR, Port: 80},
			{Protocol: tcpProtocol, CIDR: anyIPv4CIDR, Port: 443},
			{Protocol: tcpProtocol, CIDR: anyIPv4CIDR, Port: 53},
			{Protocol: udpProtocol, CIDR: anyIPv4CIDR, Port: 53},
		}, nil
	case policyProfileCompat:
		return []sdk.NetworkRule{
			{Protocol: tcpProtocol, CIDR: anyIPv4CIDR, Port: 0},
			{Protocol: udpProtocol, CIDR: anyIPv4CIDR, Port: 0},
		}, nil
	default:
		return nil, fmt.Errorf("unknown policy profile %q (want deny-all, balanced or sbx-compat)", profile)
	}
}

func mergeProfileRules(profile string, explicit []sdk.NetworkRule) ([]sdk.NetworkRule, error) {
	profileRules, err := profileRules(profile)
	if err != nil {
		return nil, err
	}
	out := append([]sdk.NetworkRule(nil), profileRules...)
	seen := make(map[sdk.NetworkRule]struct{}, len(out))
	for _, rule := range out {
		seen[rule] = struct{}{}
	}
	for _, rule := range explicit {
		if _, exists := seen[rule]; exists {
			continue
		}
		seen[rule] = struct{}{}
		out = append(out, rule)
	}
	return out, nil
}
