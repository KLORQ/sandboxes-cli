package command

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	sdk "github.com/KLORQ/sandboxes-go-sdk"
)

func TestParsePublishSpec(t *testing.T) {
	for _, tc := range []struct {
		value string
		host  uint16
		guest uint16
		ok    bool
	}{
		{"8080:3000", 8080, 3000, true},
		{"8080:3000/tcp", 8080, 3000, true},
		{"8080:3000/udp", 8080, 3000, true},
		{"0:3000", 0, 0, false},
		{"8080", 0, 8080, true},
		{"8080:0", 0, 0, false},
		{"a:b", 0, 0, false},
	} {
		port, err := parsePublishSpec(tc.value)
		if (err == nil) != tc.ok || port.Guest != tc.guest || (tc.host != 0 && port.Host != tc.host) || (tc.host == 0 && tc.ok && port.Host == 0) {
			t.Fatalf("parsePublishSpec(%q)=%+v,%v", tc.value, port, err)
		}
	}
}

func TestParsePortSpecHostIPAndIPv6(t *testing.T) {
	for _, tc := range []struct {
		value  string
		hostIP string
		host   uint16
		guest  uint16
		proto  string
		ok     bool
	}{
		{value: "127.0.0.1:8080:3000/tcp4", hostIP: "127.0.0.1", host: 8080, guest: 3000, proto: "tcp", ok: true},
		{value: "[::1]:8080:3000/tcp6", hostIP: "::1", host: 8080, guest: 3000, proto: "tcp", ok: true},
		{value: "[::1]:3000/udp6", hostIP: "::1", guest: 3000, proto: "udp", ok: true},
		{value: "8080/tcp6", hostIP: "::1", guest: 8080, proto: "tcp", ok: true},
		{value: "::1:8080:3000/tcp6", ok: false},
		{value: "192.0.2.10:8080:3000", ok: false},
		{value: "127.0.0.1:8080:3000/tcp6", ok: false},
		{value: "[::1]:8080:3000/tcp4", ok: false},
	} {
		port, err := parsePortSpec(tc.value, false)
		if (err == nil) != tc.ok {
			t.Fatalf("parsePortSpec(%q)=%+v,%v", tc.value, port, err)
		}
		if !tc.ok {
			continue
		}
		if port.HostIP != tc.hostIP || port.Host != tc.host || port.Guest != tc.guest || port.Protocol != tc.proto {
			t.Fatalf("parsePortSpec(%q)=%+v", tc.value, port)
		}
	}
}

func TestPortsForDisplaysIPv6Family(t *testing.T) {
	ports := portsFor(&sdk.Sandbox{Ports: []sdk.Port{{Host: 8080, Guest: 3000, Protocol: "tcp", HostIP: "::1"}}})
	if len(ports) != 1 || ports[0].HostIP != "::1" || ports[0].Protocol != "tcp6" {
		t.Fatalf("ports=%+v", ports)
	}
}

func TestApplyPortChangesSeparatesHostIPAndProtocol(t *testing.T) {
	existing := []sdk.Port{{Host: 8080, Guest: 3000, Protocol: "tcp", HostIP: "127.0.0.1"}}
	added, err := applyPortChanges(existing, []sdk.Port{{Host: 8080, Guest: 3001, Protocol: "tcp", HostIP: "::1"}}, nil)
	if err != nil || len(added) != 2 {
		t.Fatalf("added=%+v err=%v", added, err)
	}
	if _, err := applyPortChanges(added, []sdk.Port{{Host: 8080, Guest: 3002, Protocol: "tcp", HostIP: "::1"}}, nil); err == nil {
		t.Fatal("duplicate IPv6 host port accepted")
	}
	removed, err := applyPortChanges(added, nil, []sdk.Port{{Host: 8080, Guest: 3001, Protocol: "tcp", HostIP: "::1"}})
	if err != nil || len(removed) != 1 || portHostIP(removed[0]) != "127.0.0.1" {
		t.Fatalf("removed=%+v err=%v", removed, err)
	}
}

func TestCreatePassesPublishedPorts(t *testing.T) {
	sandbox := &recordingCreateSandbox{}
	var out bytes.Buffer
	runner := &Runner{Out: &out, Err: &out, NewClient: func(string) (sdk.Client, error) { return fakeClient{sandbox: sandbox}, nil }}
	if code := runner.Run(context.Background(), []string{"create", "--publish", "8080:3000", "--publish", "8443:443/tcp", "dev"}); code != 0 {
		t.Fatalf("exit=%d output=%q", code, out.String())
	}
	if len(sandbox.request.Ports) != 2 || sandbox.request.Ports[0].Host != 8080 || sandbox.request.Ports[1].Guest != 443 {
		t.Fatalf("ports=%+v", sandbox.request.Ports)
	}
	if code := runner.Run(context.Background(), []string{"create", "--publish", "8080:3000", "--publish", "8080:4000", "dev"}); code != 2 {
		t.Fatalf("duplicate host exit=%d", code)
	}
}

func TestRunPassesPublishedPortsOnCreate(t *testing.T) {
	workspace := t.TempDir()
	sandboxes := &runSandbox{}
	sessions := &fakeSessions{}
	runner, out, stderr := runTestRunner(t, runClient{sandboxes: sandboxes, sessions: sessions}, "")
	if code := runner.Run(context.Background(), []string{"run", "--publish", "8080:3000", "--name", "dev", "shell", workspace}); code != 0 {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, out.String(), stderr.String())
	}
	if len(sandboxes.created.Ports) != 1 || sandboxes.created.Ports[0].Host != 8080 {
		t.Fatalf("ports=%+v", sandboxes.created.Ports)
	}
}

func TestPortsCommandListsPorts(t *testing.T) {
	sandbox := &lifecycleSandbox{items: []sdk.Sandbox{{
		ID: "sb-1", Name: "dev", Ports: []sdk.Port{{Host: 8080, Guest: 3000, Protocol: "tcp"}},
	}}}
	var out bytes.Buffer
	runner := &Runner{Out: &out, Err: &out, NewClient: func(string) (sdk.Client, error) { return fakeClient{sandbox: sandbox}, nil }}
	if code := runner.Run(context.Background(), []string{"ports", "dev"}); code != 0 {
		t.Fatalf("exit=%d output=%q", code, out.String())
	}
	if !strings.Contains(out.String(), "HOST IP") || !strings.Contains(out.String(), "SANDBOX PORT") ||
		!strings.Contains(out.String(), "127.0.0.1") || !strings.Contains(out.String(), "tcp4") {
		t.Fatalf("unexpected output: %q", out.String())
	}
	var jsonOut bytes.Buffer
	runner.Out, runner.Err = &jsonOut, &jsonOut
	if code := runner.Run(context.Background(), []string{"ports", "--json", "dev"}); code != 0 {
		t.Fatalf("json exit=%d output=%q", code, jsonOut.String())
	}
	var ports []portOutput
	if err := json.Unmarshal(jsonOut.Bytes(), &ports); err != nil || len(ports) != 1 || ports[0].HostPort != 8080 {
		t.Fatalf("ports=%+v err=%v", ports, err)
	}
}

type portUpdateClient struct {
	fakeClient
	base  *lifecycleSandbox
	ports []sdk.Port
}

func (p *portUpdateClient) PortService() sdk.PortService { return p }

func (p *portUpdateClient) UpdatePorts(_ context.Context, _ string, ports []sdk.Port) (*sdk.Sandbox, error) {
	p.ports = append([]sdk.Port(nil), ports...)
	if p.base != nil && len(p.base.items) > 0 {
		p.base.items[0].Ports = p.ports
	}
	return &sdk.Sandbox{ID: "sb-1", Name: "dev", Ports: ports}, nil
}

func TestPortsDynamicPublishAndUnpublish(t *testing.T) {
	base := &lifecycleSandbox{items: []sdk.Sandbox{{ID: "sb-1", Name: "dev"}}}
	client := &portUpdateClient{fakeClient: fakeClient{sandbox: base}, base: base}
	var out bytes.Buffer
	runner := &Runner{Out: &out, Err: &out, NewClient: func(string) (sdk.Client, error) { return client, nil }}
	if code := runner.Run(context.Background(), []string{"ports", "--publish", "18090:8080", "dev"}); code != 0 {
		t.Fatalf("publish exit=%d output=%q", code, out.String())
	}
	if len(client.ports) != 1 || client.ports[0].Host != 18090 {
		t.Fatalf("ports=%+v", client.ports)
	}
	if !strings.Contains(out.String(), "Published 127.0.0.1:18090 -> 8080/tcp4") {
		t.Fatalf("publish output=%q", out.String())
	}
	out.Reset()
	if code := runner.Run(context.Background(), []string{"ports", "--publish", "18090:8081", "dev"}); code != 1 {
		t.Fatalf("duplicate publish exit=%d", code)
	}
	out.Reset()
	if code := runner.Run(context.Background(), []string{"ports", "--unpublish", "18090:8080", "dev"}); code != 0 {
		t.Fatalf("unpublish exit=%d output=%q", code, out.String())
	}
	if len(client.ports) != 0 {
		t.Fatalf("ports after unpublish=%+v", client.ports)
	}
	out.Reset()
	if code := runner.Run(context.Background(), []string{"ports", "--unpublish", "18090:8080", "dev"}); code != 1 {
		t.Fatalf("missing unpublish exit=%d", code)
	}
}

func TestPortsDynamicEphemeralPublish(t *testing.T) {
	base := &lifecycleSandbox{items: []sdk.Sandbox{{ID: "sb-1", Name: "dev"}}}
	client := &portUpdateClient{fakeClient: fakeClient{sandbox: base}, base: base}
	var out bytes.Buffer
	runner := &Runner{Out: &out, Err: &out, NewClient: func(string) (sdk.Client, error) { return client, nil }}
	if code := runner.Run(context.Background(), []string{"ports", "--publish", "8080", "dev"}); code != 0 {
		t.Fatalf("publish exit=%d output=%q", code, out.String())
	}
	if len(client.ports) != 1 || client.ports[0].Host == 0 || client.ports[0].Guest != 8080 {
		t.Fatalf("ports=%+v", client.ports)
	}
	out.Reset()
	if code := runner.Run(context.Background(), []string{"ports", "--unpublish", "8080", "dev"}); code != 0 {
		t.Fatalf("guest-only unpublish exit=%d output=%q", code, out.String())
	}
	if len(client.ports) != 0 || !strings.Contains(out.String(), "Unpublish requested for port") {
		t.Fatalf("ports=%+v output=%q", client.ports, out.String())
	}
}
