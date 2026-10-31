package command

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"slices"
	"strings"
	"testing"

	sdk "github.com/KLORQ/sandboxes-go-sdk"
)

func TestEvaluatePolicy(t *testing.T) {
	ip := net.ParseIP("10.2.3.4")
	allow := []sdk.NetworkRule{{Protocol: "tcp", CIDR: "10.0.0.0/8", Port: 443}}
	deny := []sdk.NetworkRule{{Protocol: "tcp", CIDR: "10.2.0.0/16", Port: 443}}
	if allowed, reason := evaluatePolicy(allow, nil, "tcp", ip, 443); !allowed || !strings.Contains(reason, "allow") {
		t.Fatalf("allow=%v reason=%s", allowed, reason)
	}
	if allowed, reason := evaluatePolicy(allow, deny, "tcp", ip, 443); allowed || !strings.Contains(reason, "deny") {
		t.Fatalf("deny precedence=%v reason=%s", allowed, reason)
	}
	if allowed, _ := evaluatePolicy(allow, nil, "tcp", ip, 80); allowed {
		t.Fatal("port mismatch allowed")
	}
	anyPort := []sdk.NetworkRule{{Protocol: "udp", CIDR: "10.0.0.0/8"}}
	if allowed, _ := evaluatePolicy(anyPort, nil, "udp", ip, 53); !allowed {
		t.Fatal("port zero did not match")
	}
	if allowed, reason := evaluatePolicy(nil, nil, "tcp", ip, 443); allowed || reason != "default deny" {
		t.Fatalf("default=%v %s", allowed, reason)
	}
	emptyProtocol := []sdk.NetworkRule{{CIDR: "10.0.0.0/8", Port: 443}}
	if allowed, _ := evaluatePolicy(emptyProtocol, nil, "tcp", ip, 443); !allowed {
		t.Fatal("empty protocol must default to tcp")
	}
	if allowed, _ := evaluatePolicy(emptyProtocol, nil, "udp", ip, 443); allowed {
		t.Fatal("empty protocol incorrectly matched udp")
	}
}

func TestParsePolicyDestinationRejectsCIDR(t *testing.T) {
	if _, err := parsePolicyDestination("10.0.0.0/8"); err == nil {
		t.Fatal("CIDR destination accepted")
	}
	if _, err := parsePolicyDestination("2001:db8::1"); err == nil {
		t.Fatal("IPv6 destination accepted")
	}
}

func TestPolicyListAndCheck(t *testing.T) {
	sandbox := &lifecycleSandbox{items: []sdk.Sandbox{{
		ID: "sb-1", Name: "dev",
		Allow: []sdk.NetworkRule{{Protocol: "tcp", CIDR: "10.0.0.0/8", Port: 443}},
		Deny:  []sdk.NetworkRule{{Protocol: "tcp", CIDR: "10.9.0.0/16", Port: 443}},
	}}}
	var out bytes.Buffer
	runner := &Runner{Out: &out, Err: &out, NewClient: func(string) (sdk.Client, error) { return fakeClient{sandbox: sandbox}, nil }}
	if code := runner.Run(context.Background(), []string{"policy", "ls", "dev"}); code != 0 {
		t.Fatalf("ls exit=%d output=%q", code, out.String())
	}
	if !strings.Contains(out.String(), "10.0.0.0/8") || !strings.Contains(out.String(), "deny") {
		t.Fatalf("ls output=%q", out.String())
	}
	out.Reset()
	if code := runner.Run(context.Background(), []string{"policy", "ls", "--json", "dev"}); code != 0 {
		t.Fatalf("json exit=%d output=%q", code, out.String())
	}
	var rules []policyRuleOutput
	if err := json.Unmarshal(out.Bytes(), &rules); err != nil || len(rules) != 2 || rules[0].Action != "allow" {
		t.Fatalf("rules=%+v err=%v", rules, err)
	}
	out.Reset()
	if code := runner.Run(context.Background(), []string{"policy", "check", "dev", "10.1.2.3", "443"}); code != 0 {
		t.Fatalf("allowed check exit=%d output=%q", code, out.String())
	}
	out.Reset()
	if code := runner.Run(context.Background(), []string{"policy", "check", "dev", "10.9.1.2", "443"}); code != 1 {
		t.Fatalf("denied check exit=%d output=%q", code, out.String())
	}
	out.Reset()
	if code := runner.Run(context.Background(), []string{"policy", "allow", "dev", "10.0.0.0/8"}); code != 1 {
		t.Fatalf("dynamic policy exit=%d output=%q", code, out.String())
	}
}

type policyUpdateClient struct {
	fakeClient
	base        *lifecycleSandbox
	allow, deny []sdk.NetworkRule
}

func (p *policyUpdateClient) PolicyService() sdk.PolicyService { return p }

func (p *policyUpdateClient) UpdatePolicy(_ context.Context, id string, allow, deny []sdk.NetworkRule) (*sdk.Sandbox, error) {
	_ = id
	p.allow = append([]sdk.NetworkRule(nil), allow...)
	p.deny = append([]sdk.NetworkRule(nil), deny...)
	if p.base != nil && len(p.base.items) > 0 {
		p.base.items[0].Allow = p.allow
		p.base.items[0].Deny = p.deny
	}
	return &sdk.Sandbox{ID: "sb-1", Name: "dev", Allow: allow, Deny: deny}, nil
}

func (p *policyUpdateClient) MutatePolicy(ctx context.Context, id, action string, rule sdk.NetworkRule) (*sdk.Sandbox, error) {
	allow := append([]sdk.NetworkRule(nil), p.base.items[0].Allow...)
	deny := append([]sdk.NetworkRule(nil), p.base.items[0].Deny...)
	switch action {
	case "allow":
		allow = append(allow, rule)
	case "deny":
		deny = append(deny, rule)
	case "rm":
		if !slices.Contains(allow, rule) && !slices.Contains(deny, rule) {
			return nil, errors.New("policy rule not found")
		}
		allow = slices.DeleteFunc(allow, func(r sdk.NetworkRule) bool { return r == rule })
		deny = slices.DeleteFunc(deny, func(r sdk.NetworkRule) bool { return r == rule })
	}
	return p.UpdatePolicy(ctx, id, allow, deny)
}

func TestPolicyDynamicUpdates(t *testing.T) {
	base := &lifecycleSandbox{items: []sdk.Sandbox{{
		ID: "sb-1", Name: "dev",
		Allow: []sdk.NetworkRule{{Protocol: "tcp", CIDR: "10.0.0.0/8", Port: 443}},
	}}}
	client := &policyUpdateClient{fakeClient: fakeClient{sandbox: base}, base: base}
	var out bytes.Buffer
	runner := &Runner{Out: &out, Err: &out, NewClient: func(string) (sdk.Client, error) { return client, nil }}
	if code := runner.Run(context.Background(), []string{"policy", "allow", "dev", "0.0.0.0/0:80"}); code != 0 {
		t.Fatalf("allow exit=%d output=%q", code, out.String())
	}
	if len(client.allow) != 2 || client.allow[1].Port != 80 {
		t.Fatalf("allow=%+v", client.allow)
	}
	out.Reset()
	if code := runner.Run(context.Background(), []string{"policy", "deny", "dev", "10.9.0.0/16:443"}); code != 0 {
		t.Fatalf("deny exit=%d output=%q", code, out.String())
	}
	if len(client.deny) != 1 {
		t.Fatalf("deny=%+v", client.deny)
	}
	out.Reset()
	if code := runner.Run(context.Background(), []string{"policy", "rm", "dev", "10.0.0.0/8:443"}); code != 0 {
		t.Fatalf("rm exit=%d output=%q", code, out.String())
	}
	if len(client.allow) != 1 || client.allow[0].Port != 80 {
		t.Fatalf("allow after rm=%+v", client.allow)
	}
	out.Reset()
	if code := runner.Run(context.Background(), []string{"policy", "rm", "dev", "192.0.2.0/24"}); code != 1 {
		t.Fatalf("missing rm exit=%d output=%q", code, out.String())
	}
}
