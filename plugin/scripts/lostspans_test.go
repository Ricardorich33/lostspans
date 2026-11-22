package main

import (
	"bytes"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// envScope builds a Kubernetes container scope from NAME=VALUE pairs.
func envScope(pairs ...string) *scope {
	sc := &scope{Label: "test", File: "t.yaml", Platform: "kubernetes"}
	for i, p := range pairs {
		k, v, _ := strings.Cut(p, "=")
		sc.Vars = append(sc.Vars, &envVar{Name: k, Value: v, Known: true, File: "t.yaml", Line: i + 1})
	}
	return sc
}

func rulesOf(fs []Finding) []string {
	var out []string
	for _, f := range fs {
		out = append(out, f.Level+" "+f.Rule)
	}
	sort.Strings(out)
	return out
}

func TestRules(t *testing.T) {
	cases := []struct {
		name string
		env  []string
		want []string // "SEVERITY RULE", sorted; empty means quiet
	}{
		// Quiet cases: correct settings from the spec's own examples and real deployments.
		{"base endpoint", []string{"OTEL_EXPORTER_OTLP_ENDPOINT=http://otel-collector:4318"}, nil},
		{"base endpoint with custom path", []string{"OTEL_EXPORTER_OTLP_ENDPOINT=http://collector:4318/mycollector/"}, nil},
		{"signal endpoints with paths", []string{"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT=http://c:4318/v1/traces", "OTEL_EXPORTER_OTLP_METRICS_ENDPOINT=https://collector.example.com/v1/metrics"}, nil},
		{"vendor https endpoint without port", []string{"OTEL_EXPORTER_OTLP_ENDPOINT=https://otlp.example.com"}, nil},
		{"grpc base endpoint", []string{"OTEL_EXPORTER_OTLP_ENDPOINT=http://otel-collector:4317", "OTEL_EXPORTER_OTLP_PROTOCOL=grpc"}, nil},
		{"grpc port with no protocol", []string{"OTEL_EXPORTER_OTLP_ENDPOINT=http://otel-collector:4317"}, nil},
		{"grpc signal endpoint without path", []string{"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT=http://otel-collector:4317", "OTEL_EXPORTER_OTLP_TRACES_PROTOCOL=grpc"}, nil},
		{"signal endpoint ignored when exporter isn't otlp", []string{"OTEL_EXPORTER_OTLP_METRICS_ENDPOINT=http://c:4318", "OTEL_METRICS_EXPORTER=prometheus"}, nil},
		{"base endpoint unused", []string{"OTEL_EXPORTER_OTLP_ENDPOINT=http://c:4318/v1/traces", "OTEL_TRACES_EXPORTER=none", "OTEL_METRICS_EXPORTER=none", "OTEL_LOGS_EXPORTER=none"}, nil},
		{"good values", []string{"OTEL_EXPORTER_OTLP_TIMEOUT=10000", "OTEL_METRIC_EXPORT_INTERVAL=60000", "OTEL_BSP_SCHEDULE_DELAY=50",
			"OTEL_TRACES_SAMPLER=parentbased_traceidratio", "OTEL_TRACES_SAMPLER_ARG=0.1", "OTEL_PROPAGATORS=tracecontext,baggage,b3",
			"OTEL_SDK_DISABLED=FALSE", "OTEL_EXPORTER_OTLP_INSECURE=true", "OTEL_EXPORTER_OTLP_COMPRESSION=gzip",
			"OTEL_EXPORTER_OTLP_HEADERS=Authorization=Bearer%20abc,x-tenant=t1", "OTEL_RESOURCE_ATTRIBUTES=service.version=1.2,deployment.environment=prod",
			"OTEL_TRACES_EXPORTER=otlp,console", "OTEL_METRICS_EXPORTER=otlp_proto_http", "OTEL_LOGS_EXPORTER=none"}, nil},
		{"parent based ratio zero", []string{"OTEL_TRACES_SAMPLER=parentbased_traceidratio", "OTEL_TRACES_SAMPLER_ARG=0"}, nil},
		{"timeout zero means no limit", []string{"OTEL_EXPORTER_OTLP_TIMEOUT=0"}, nil},
		{"language and project names", []string{"OTEL_GO_X_OBSERVABILITY=true", "OTEL_COLLECTOR_NAME=otel-collector", "OTEL_PYTHON_LOG_CORRELATION=true", "OTEL_EXPERIMENTAL_SDK_TELEMETRY_VERSION=latest"}, nil},

		// Endpoints.
		{"LS101 base endpoint with signal path", []string{"OTEL_EXPORTER_OTLP_ENDPOINT=http://c:4318/v1/traces"}, []string{"HIGH LS101"}},
		{"LS101 with trailing slash", []string{"OTEL_EXPORTER_OTLP_ENDPOINT=http://c:4318/v1/metrics/"}, []string{"HIGH LS101"}},
		{"LS101 and LS105 on the grpc port", []string{"OTEL_EXPORTER_OTLP_ENDPOINT=http://c:4317/v1/traces"}, []string{"HIGH LS101", "MEDIUM LS105"}},
		{"LS102 signal endpoint without path", []string{"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT=http://c:4318"}, []string{"HIGH LS102"}},
		{"LS102 with root path", []string{"OTEL_EXPORTER_OTLP_LOGS_ENDPOINT=http://c:4318/", "OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf"}, []string{"HIGH LS102"}},
		{"LS103 wrong signal path", []string{"OTEL_EXPORTER_OTLP_METRICS_ENDPOINT=http://c:4318/v1/traces"}, []string{"HIGH LS103"}},
		{"LS104 no scheme", []string{"OTEL_EXPORTER_OTLP_ENDPOINT=otel-collector:4318"}, []string{"HIGH LS104"}},
		{"LS104 grpc host:port", []string{"OTEL_EXPORTER_OTLP_ENDPOINT=otel-collector:4317", "OTEL_EXPORTER_OTLP_PROTOCOL=grpc"}, []string{"MEDIUM LS104"}},
		{"LS104 grpc scheme", []string{"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT=grpc://c:4317"}, []string{"HIGH LS104"}},
		{"LS105 http on grpc port", []string{"OTEL_EXPORTER_OTLP_ENDPOINT=http://c:4317", "OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf"}, []string{"MEDIUM LS105"}},
		{"LS105 grpc on http port", []string{"OTEL_EXPORTER_OTLP_ENDPOINT=http://c:4318", "OTEL_EXPORTER_OTLP_PROTOCOL=grpc"}, []string{"MEDIUM LS105"}},
		{"LS106 http without port", []string{"OTEL_EXPORTER_OTLP_ENDPOINT=http://otel-collector"}, []string{"LOW LS106"}},
		{"LS107 localhost", []string{"OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318"}, []string{"MEDIUM LS107"}},
		{"LS107 loopback IP", []string{"OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:4318"}, []string{"MEDIUM LS107"}},

		// Enums.
		{"LS201 protocol http", []string{"OTEL_EXPORTER_OTLP_PROTOCOL=http"}, []string{"HIGH LS201"}},
		{"LS201 signal protocol", []string{"OTEL_EXPORTER_OTLP_TRACES_PROTOCOL=grpc/protobuf"}, []string{"HIGH LS201"}},
		{"LS202 protocol case", []string{"OTEL_EXPORTER_OTLP_PROTOCOL=GRPC"}, []string{"MEDIUM LS202"}},
		{"LS202 exporter case", []string{"OTEL_TRACES_EXPORTER=OTLP"}, []string{"MEDIUM LS202"}},
		{"LS203 jaeger", []string{"OTEL_TRACES_EXPORTER=jaeger"}, []string{"HIGH LS203"}},
		{"LS203 logging", []string{"OTEL_LOGS_EXPORTER=logging"}, []string{"LOW LS203"}},
		{"LS203 unknown", []string{"OTEL_METRICS_EXPORTER=otlp,statsd"}, []string{"MEDIUM LS203"}},
		{"LS204 sampler", []string{"OTEL_TRACES_SAMPLER=ratio"}, []string{"MEDIUM LS204"}},
		{"LS205 propagator", []string{"OTEL_PROPAGATORS=tracecontext,w3c"}, []string{"MEDIUM LS205"}},
		{"LS206 compression", []string{"OTEL_EXPORTER_OTLP_COMPRESSION=zstd"}, []string{"MEDIUM LS206"}},

		// Sampling.
		{"LS301 ratio zero", []string{"OTEL_TRACES_SAMPLER=traceidratio", "OTEL_TRACES_SAMPLER_ARG=0"}, []string{"HIGH LS301"}},
		{"LS302 percent", []string{"OTEL_TRACES_SAMPLER=parentbased_traceidratio", "OTEL_TRACES_SAMPLER_ARG=10"}, []string{"MEDIUM LS302"}},
		{"LS302 text", []string{"OTEL_TRACES_SAMPLER=traceidratio", "OTEL_TRACES_SAMPLER_ARG=10%"}, []string{"MEDIUM LS302"}},
		{"LS303 arg without sampler", []string{"OTEL_TRACES_SAMPLER_ARG=0.1"}, []string{"MEDIUM LS303"}},
		{"LS304 always off", []string{"OTEL_TRACES_SAMPLER=always_off"}, []string{"LOW LS304"}},

		// Numbers.
		{"LS401 timeout in seconds", []string{"OTEL_EXPORTER_OTLP_TIMEOUT=10"}, []string{"MEDIUM LS401"}},
		{"LS401 batch timeout", []string{"OTEL_BSP_EXPORT_TIMEOUT=30"}, []string{"MEDIUM LS401"}},
		{"LS402 unit", []string{"OTEL_EXPORTER_OTLP_TRACES_TIMEOUT=10s"}, []string{"MEDIUM LS402"}},
		{"LS402 negative", []string{"OTEL_BSP_SCHEDULE_DELAY=-1"}, []string{"MEDIUM LS402"}},
		{"LS402 integer", []string{"OTEL_BSP_MAX_QUEUE_SIZE=2k"}, []string{"MEDIUM LS402"}},
		{"LS403 interval", []string{"OTEL_METRIC_EXPORT_INTERVAL=60"}, []string{"MEDIUM LS403"}},
		{"LS404 batch over queue", []string{"OTEL_BSP_MAX_QUEUE_SIZE=100", "OTEL_BSP_MAX_EXPORT_BATCH_SIZE=512"}, []string{"LOW LS404"}},

		// Lists.
		{"LS501 colon", []string{"OTEL_EXPORTER_OTLP_HEADERS=Authorization: Bearer abc"}, []string{"HIGH LS501"}},
		{"LS501 bare key", []string{"OTEL_EXPORTER_OTLP_TRACES_HEADERS=x-tenant=a,api-key"}, []string{"HIGH LS501"}},
		{"LS502 semicolon", []string{"OTEL_EXPORTER_OTLP_HEADERS=a=1;b=2"}, []string{"MEDIUM LS502"}},
		{"LS503 attribute without value", []string{"OTEL_RESOURCE_ATTRIBUTES=service.version=1,team"}, []string{"MEDIUM LS503"}},
		{"LS504 attribute semicolon", []string{"OTEL_RESOURCE_ATTRIBUTES=a=1;b=2"}, []string{"MEDIUM LS504"}},
		{"LS505 bad escape", []string{"OTEL_RESOURCE_ATTRIBUTES=note=100%zz"}, []string{"LOW LS505"}},

		// Names, booleans, empty values.
		{"LS601 typo", []string{"OTEL_EXPORTER_OTLP_TRACE_ENDPOINT=http://c:4318/v1/traces"}, []string{"MEDIUM LS601"}},
		{"LS601 service name", []string{"OTEL_SERVICENAME=api"}, []string{"MEDIUM LS601"}},
		{"LS602 boolean", []string{"OTEL_SDK_DISABLED=1"}, []string{"MEDIUM LS602"}},
		{"LS603 empty endpoint", []string{"OTEL_EXPORTER_OTLP_ENDPOINT="}, []string{"MEDIUM LS603"}},
		{"LS603 empty other", []string{"OTEL_SERVICE_NAME="}, []string{"LOW LS603"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := rulesOf(check(envScope(tc.env...)))
			if strings.Join(got, ",") != strings.Join(tc.want, ",") {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestCertificatePathsRequireMounts(t *testing.T) {
	const cert = "OTEL_EXPORTER_OTLP_CERTIFICATE=/etc/otel/ca.pem"
	if got := rulesOf(check(envScope(cert))); strings.Join(got, ",") != "MEDIUM LS108" {
		t.Errorf("missing mount: got %v", got)
	}
	for _, mount := range []string{"/etc/otel", "/etc/otel/ca.pem", "/"} {
		sc := envScope(cert)
		sc.Mounts = []string{mount}
		if got := check(sc); len(got) != 0 {
			t.Errorf("mount %s should cover the path, got %v", mount, rulesOf(got))
		}
	}
	sc := envScope(cert)
	sc.Mounts = []string{"/etc/otel-old"}
	if got := rulesOf(check(sc)); strings.Join(got, ",") != "MEDIUM LS108" {
		t.Errorf("mount prefix must be a path boundary, got %v", got)
	}
	sc = envScope(cert)
	sc.Platform = "compose"
	if got := check(sc); len(got) != 0 {
		t.Errorf("Compose scopes have no Kubernetes volumeMounts, got %v", rulesOf(got))
	}
	for _, name := range []string{"OTEL_EXPORTER_OTLP_CLIENT_KEY", "OTEL_EXPORTER_OTLP_CLIENT_CERTIFICATE"} {
		sc := envScope(name + "=/etc/otel/client.pem")
		if got := rulesOf(check(sc)); strings.Join(got, ",") != "MEDIUM LS108" {
			t.Errorf("%s: got %v", name, got)
		}
	}
	for _, signal := range []string{"TRACES", "METRICS", "LOGS"} {
		for _, suffix := range []string{"CERTIFICATE", "CLIENT_KEY", "CLIENT_CERTIFICATE"} {
			name := "OTEL_EXPORTER_OTLP_" + signal + "_" + suffix
			sc := envScope(name + "=/etc/otel/client.pem")
			if got := rulesOf(check(sc)); strings.Join(got, ",") != "MEDIUM LS108" {
				t.Errorf("%s: got %v", name, got)
			}
		}
	}
	for _, path := range []string{
		"/etc/ssl/certs/ca-certificates.crt",
		"/etc/pki/tls/certs/ca-bundle.crt",
		"/usr/share/ca-certificates/mozilla/test.crt",
		"/usr/local/share/ca-certificates/test.crt",
	} {
		sc := envScope("OTEL_EXPORTER_OTLP_CERTIFICATE=" + path)
		if got := check(sc); len(got) != 0 {
			t.Errorf("system trust path %s should be quiet, got %v", path, rulesOf(got))
		}
	}
	const clientKeyPath = "/etc/otel/private.key"
	sc = envScope("OTEL_EXPORTER_OTLP_CLIENT_KEY=" + clientKeyPath)
	fs := check(sc)
	if len(fs) != 1 || fs[0].Rule != "LS108" {
		t.Fatalf("client key: got %v", rulesOf(fs))
	}
	if strings.Contains(fs[0].Value+fs[0].Message+fs[0].Fix, clientKeyPath) {
		t.Errorf("client key path leaked in finding: %+v", fs[0])
	}
}

func TestLocalhostWithCollectorSidecar(t *testing.T) {
	sc := envScope("OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318")
	sc.LocalCollector = true
	if got := check(sc); len(got) != 0 {
		t.Errorf("got %v", rulesOf(got))
	}
	sc = envScope("OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318")
	sc.Platform = "envfile"
	if got := check(sc); len(got) != 0 {
		t.Errorf("env files don't say where they run, got %v", rulesOf(got))
	}
}

func TestReferenceEntriesQuiet(t *testing.T) {
	for _, val := range []string{"${OTEL_RESOURCE_ATTRIBUTES},service.criticality=low", "$(BASE_ATTRS),team=a", "$EXTRA,team=a"} {
		sc := &scope{Label: "t", Platform: "compose", Vars: []*envVar{{Name: "OTEL_RESOURCE_ATTRIBUTES", Value: val, Why: "uses a variable"}}}
		if got := check(sc); len(got) != 0 {
			t.Errorf("%s: got %v", val, rulesOf(got))
		}
	}
}

func TestHeaderValuesHidden(t *testing.T) {
	fs := check(envScope("OTEL_EXPORTER_OTLP_HEADERS=Authorization: Bearer s3cret-token"))
	if len(fs) == 0 {
		t.Fatal("no finding")
	}
	for _, f := range fs {
		if strings.Contains(f.Value+f.Message+f.Fix, "s3cret") {
			t.Errorf("secret printed: %+v", f)
		}
	}
	v := &envVar{Name: "OTEL_EXPORTER_OTLP_ENDPOINT", Value: "https://user:pa55@otlp.example.com", Known: true}
	if d := display(v); strings.Contains(d, "pa55") {
		t.Errorf("password printed: %s", d)
	}
}

func TestKubeExpand(t *testing.T) {
	known := map[string]*envVar{
		"HOST":   {Name: "HOST", Value: "otel-collector", Known: true},
		"SECRET": {Name: "SECRET", Why: "set from valueFrom"},
	}
	cases := []struct {
		in, out string
		ok      bool
	}{
		{"http://$(HOST):4318", "http://otel-collector:4318", true},
		{"$$(HOST)", "$(HOST)", true},
		{"$(MISSING)", "$(MISSING)", true},
		{"key=$(SECRET)", "key=$(SECRET)", false},
		{"$(HOST", "$(HOST", true},
		{"a$b", "a$b", true},
	}
	for _, c := range cases {
		out, ok, _ := kubeExpand(c.in, known)
		if out != c.out || ok != c.ok {
			t.Errorf("kubeExpand(%q) = %q, %v; want %q, %v", c.in, out, ok, c.out, c.ok)
		}
	}
}

func TestComposeExpand(t *testing.T) {
	vars := map[string]*envVar{
		"HOST":  {Name: "HOST", Value: "otel-collector", Known: true},
		"EMPTY": {Name: "EMPTY", Value: "", Known: true},
	}
	cases := []struct {
		in, out string
		ok      bool
	}{
		{"http://${HOST}:4318", "http://otel-collector:4318", true},
		{"http://$HOST:4318", "http://otel-collector:4318", true},
		{"${MISSING:-http://c:4318}", "http://c:4318", true},
		{"${EMPTY:-x}", "x", true},
		{"${EMPTY-x}", "", true},
		{"${HOST:+set}", "set", true},
		{"$${HOST}", "${HOST}", true},
		{"${MISSING}", "${MISSING}", false},
	}
	for _, c := range cases {
		out, ok, _ := composeExpand(c.in, vars)
		if out != c.out || ok != c.ok {
			t.Errorf("composeExpand(%q) = %q, %v; want %q, %v", c.in, out, ok, c.out, c.ok)
		}
	}
}

func TestParseDotenv(t *testing.T) {
	data := "# comment\nexport A=1\nB=\"two ${A}\"\nC='three ${A}'\nD=four # note\n\nE=\n"
	vars, err := parseDotenv("x.env", []byte(data), nil)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, v := range vars {
		got[v.Name] = v.Value
	}
	want := map[string]string{"A": "1", "B": "two 1", "C": "three ${A}", "D": "four", "E": ""}
	for k, w := range want {
		if got[k] != w {
			t.Errorf("%s = %q, want %q", k, got[k], w)
		}
	}
	for _, bad := range []string{"just text\n", "A=\"open\n", "1BAD=x\n", "# only\n"} {
		if _, err := parseDotenv("x.env", []byte(bad), nil); err == nil {
			t.Errorf("%q: no error", bad)
		}
	}
}

func runCLI(t *testing.T, stdin string, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := run(args, strings.NewReader(stdin), &out, &errb)
	return code, out.String(), errb.String()
}

func TestRunExitCodes(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.env")
	os.WriteFile(bad, []byte("OTEL_EXPORTER_OTLP_TIMEOUT=10\nOTEL_EXPORTER_OTLP_ENDPOINT=http://c:4318/v1/traces\n"), 0o644)
	good := filepath.Join(dir, "good.env")
	os.WriteFile(good, []byte("OTEL_EXPORTER_OTLP_ENDPOINT=http://c:4318\n"), 0o644)
	cases := []struct {
		args []string
		code int
	}{
		{[]string{good}, 0},
		{[]string{bad}, 1},
		{[]string{"--fail-on", "never", bad}, 0},
		{[]string{"--fail-on", "medium", bad}, 1},
		{[]string{"--fail-on", "bogus", bad}, 2},
		{[]string{"--format", "xml", bad}, 2},
		{[]string{}, 2},
		{[]string{filepath.Join(dir, "missing.yaml")}, 2},
	}
	for _, c := range cases {
		code, _, _ := runCLI(t, "", c.args...)
		if code != c.code {
			t.Errorf("%v: exit %d, want %d", c.args, code, c.code)
		}
	}
}

func TestStdin(t *testing.T) {
	manifest := `apiVersion: v1
kind: Pod
metadata:
  name: p
spec:
  containers:
    - name: c
      image: busybox
      env:
        - name: OTEL_EXPORTER_OTLP_PROTOCOL
          value: http
`
	code, out, _ := runCLI(t, manifest, "-")
	if code != 1 || !strings.Contains(out, "LS201") {
		t.Errorf("exit %d, output:\n%s", code, out)
	}
	code, out, errOut := runCLI(t, "", "-")
	if code != 2 || out != "" || !strings.Contains(errOut, "empty") {
		t.Errorf("empty stdin: exit %d, stdout %q, stderr %q", code, out, errOut)
	}
}
