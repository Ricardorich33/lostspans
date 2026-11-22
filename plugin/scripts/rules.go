package main

import (
	"fmt"
	"net"
	"net/url"
	pathpkg "path"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Severity orders findings. High means telemetry is lost or the exporter fails.
type Severity int

const (
	Low Severity = iota + 1
	Medium
	High
)

func (s Severity) String() string {
	switch s {
	case High:
		return "HIGH"
	case Medium:
		return "MEDIUM"
	}
	return "LOW"
}

// Finding is one problem with one variable in one scope.
type Finding struct {
	Severity Severity `json:"-"`
	Level    string   `json:"severity"`
	Rule     string   `json:"rule"`
	Scope    string   `json:"scope"`
	File     string   `json:"file"`
	Line     int      `json:"line"`
	Variable string   `json:"variable"`
	Value    string   `json:"value"`
	Message  string   `json:"message"`
	Fix      string   `json:"fix"`
}

var signals = []string{"TRACES", "METRICS", "LOGS"}

func lowerSignal(s string) string { return strings.ToLower(s) }

type checker struct {
	sc   *scope
	eff  map[string]*envVar
	out  []Finding
	seen map[string]bool
}

func (c *checker) add(sev Severity, rule string, v *envVar, msg, fix string) {
	key := rule + "\x00" + v.Name
	if c.seen[key] {
		return
	}
	c.seen[key] = true
	c.out = append(c.out, Finding{Severity: sev, Level: sev.String(), Rule: rule, Scope: c.sc.Label, File: v.File, Line: v.Line,
		Variable: v.Name, Value: display(v), Message: msg, Fix: fix})
}

// display shows a value without secrets: header values are hidden, and so is
// a password in an endpoint URL.
func display(v *envVar) string {
	if strings.Contains(v.Name, "HEADERS") {
		var keys []string
		for _, p := range strings.Split(v.Value, ",") {
			k, _, _ := strings.Cut(p, "=")
			k, _, _ = strings.Cut(k, ":")
			if k = strings.TrimSpace(k); k != "" {
				keys = append(keys, k)
			}
		}
		return "(values hidden; keys: " + strings.Join(keys, ", ") + ")"
	}
	if strings.Contains(v.Name, "PASSWORD") || strings.Contains(v.Name, "CLIENT_KEY") {
		return "(hidden)"
	}
	if !v.Known {
		return v.Value
	}
	if u, err := url.Parse(v.Value); err == nil && u.User != nil {
		u.User = url.User("hidden")
		return u.String()
	}
	return v.Value
}

// check runs every rule on one scope.
func check(sc *scope) []Finding {
	c := &checker{sc: sc, eff: sc.effective(), seen: map[string]bool{}}
	for _, name := range sortedKeys(c.eff) {
		v := c.eff[name]
		c.checkName(v)
		if !v.Known {
			// The list's shape can be wrong whatever the referenced values are.
			if v.Value != "" && (v.Name == "OTEL_RESOURCE_ATTRIBUTES" || (strings.HasSuffix(v.Name, "_HEADERS") && strings.HasPrefix(v.Name, "OTEL_EXPORTER_OTLP"))) {
				c.checkPairs(v, v.Value, v.Name != "OTEL_RESOURCE_ATTRIBUTES")
			}
			continue
		}
		if strings.TrimSpace(v.Value) == "" {
			c.checkEmpty(v)
			continue
		}
		c.checkValue(v)
	}
	c.checkEndpoints()
	c.checkFilePaths()
	c.checkSampler()
	c.checkBatchSizes()
	sort.SliceStable(c.out, func(i, j int) bool {
		if c.out[i].Severity != c.out[j].Severity {
			return c.out[i].Severity > c.out[j].Severity
		}
		return c.out[i].Line < c.out[j].Line
	})
	return c.out
}

// protocol/exporter.md defines the base and signal-specific certificate,
// client key, and client certificate variables as file paths.
var certificatePathVars = func() map[string]bool {
	m := map[string]bool{
		"OTEL_EXPORTER_OTLP_CERTIFICATE":        true,
		"OTEL_EXPORTER_OTLP_CLIENT_KEY":         true,
		"OTEL_EXPORTER_OTLP_CLIENT_CERTIFICATE": true,
	}
	for _, signal := range []string{"TRACES", "METRICS", "LOGS"} {
		for _, suffix := range []string{"CERTIFICATE", "CLIENT_KEY", "CLIENT_CERTIFICATE"} {
			m["OTEL_EXPORTER_OTLP_"+signal+"_"+suffix] = true
		}
	}
	return m
}()

var systemTrustPrefixes = []string{
	"/etc/ssl/certs",
	"/etc/pki",
	"/usr/share/ca-certificates",
	"/usr/local/share/ca-certificates",
}

// checkFilePaths reports an absolute certificate or key path that no
// volumeMount in the same Kubernetes container covers. A relative path depends
// on the image's working directory, which isn't in the input, so it isn't
// checked here.
func (c *checker) checkFilePaths() {
	if c.sc.Platform != "kubernetes" {
		return
	}
	for _, name := range sortedKeys(c.eff) {
		v := c.eff[name]
		if !certificatePathVars[name] || !v.Known {
			continue
		}
		p := strings.TrimSpace(v.Value)
		if !strings.HasPrefix(p, "/") || isSystemTrustPath(p) || pathCoveredByMount(p, c.sc.Mounts) {
			continue
		}
		shown := display(v)
		var message string
		if shown == "(hidden)" {
			message = fmt.Sprintf("%s names a file, but no volumeMount in this container covers it. If the file isn't in the image, the SDK can't read it and TLS export fails.", name)
		} else {
			message = fmt.Sprintf("%s names a file, but no volumeMount in this container covers %q. If the file isn't in the image, the SDK can't read it and TLS export fails.", name, shown)
		}
		c.add(Medium, "LS108", v, message,
			"mount the file at that path, or set the variable to the file's in-container path")
	}
}

func isSystemTrustPath(filePath string) bool {
	filePath = pathpkg.Clean(filePath)
	for _, prefix := range systemTrustPrefixes {
		prefix = pathpkg.Clean(prefix)
		if filePath == prefix || strings.HasPrefix(filePath, strings.TrimSuffix(prefix, "/")+"/") {
			return true
		}
	}
	return false
}

func pathCoveredByMount(filePath string, mounts []string) bool {
	filePath = pathpkg.Clean(filePath)
	for _, mount := range mounts {
		if filePath == mount || strings.HasPrefix(filePath, strings.TrimSuffix(mount, "/")+"/") {
			return true
		}
	}
	return false
}

func (c *checker) checkName(v *envVar) {
	if k := closestKnown(v.Name); k != "" {
		c.add(Medium, "LS601", v, fmt.Sprintf("%s isn't an OpenTelemetry SDK variable, so SDKs ignore it. It looks like a typo of %s.", v.Name, k),
			"rename it to "+k)
	}
}

func (c *checker) checkEmpty(v *envVar) {
	if strings.HasSuffix(v.Name, "_ENDPOINT") && strings.HasPrefix(v.Name, "OTEL_EXPORTER_OTLP") {
		c.add(Medium, "LS603", v, "The value is empty. The spec says an empty value counts as unset, so the exporter sends to its default, localhost.",
			"set the collector's URL, or remove the variable")
		return
	}
	if knownNames[v.Name] {
		c.add(Low, "LS603", v, "The value is empty. The spec says an empty value counts as unset, so the default applies.",
			"set a value, or remove the variable")
	}
}

func (c *checker) checkValue(v *envVar) {
	val := strings.TrimSpace(v.Value)
	n := v.Name
	switch {
	case strings.HasSuffix(n, "_PROTOCOL") && strings.HasPrefix(n, "OTEL_EXPORTER_OTLP"):
		lv := strings.ToLower(val)
		if !inList(lv, protocols) {
			c.add(High, "LS201", v, fmt.Sprintf("%q isn't an OTLP protocol. The spec allows grpc, http/protobuf and http/json. Go's autoexport fails to create the exporter, and other SDKs ignore the setting or fail.", val),
				"use http/protobuf for port 4318 or grpc for port 4317")
		} else if lv != val {
			c.add(Medium, "LS202", v, fmt.Sprintf("The spec says SDKs should accept any case, but Go's autoexport rejects %q and creates no exporter.", val),
				"write it in lower case: "+lv)
		}
	case exporters[n] != nil:
		for _, item := range splitList(val) {
			li := strings.ToLower(item)
			switch {
			case li == "jaeger":
				c.add(High, "LS203", v, "The jaeger exporter is no longer in the spec, and Go's autoexport rejects it, so no exporter is created. Jaeger accepts OTLP.",
					"use otlp and point the endpoint at Jaeger's OTLP port")
			case li == "logging":
				c.add(Low, "LS203", v, "logging is a deprecated name for console, and the spec says new SDKs shouldn't support it.",
					"use console")
			case inList(li, exporters[n]):
				if li != item {
					c.add(Medium, "LS202", v, fmt.Sprintf("The spec says SDKs should accept any case, but Go's autoexport rejects %q and creates no exporter.", item),
						"write it in lower case: "+li)
				}
			case inList(li, sdkExporters):
			default:
				c.add(Medium, "LS203", v, fmt.Sprintf("%q isn't an exporter the spec defines for %s. SDKs that don't know it ignore it or fail; Go's autoexport fails to create an exporter.", item, n),
					"use one of: "+strings.Join(exporters[n], ", "))
			}
		}
	case n == "OTEL_TRACES_SAMPLER":
		if !inList(strings.ToLower(val), samplers) {
			c.add(Medium, "LS204", v, fmt.Sprintf("%q isn't a sampler the spec defines. SDKs ignore it and use parentbased_always_on, which samples every new trace.", val),
				"use one of: "+strings.Join(samplers, ", "))
		}
	case n == "OTEL_PROPAGATORS":
		for _, item := range splitList(val) {
			if !inList(strings.ToLower(item), propagates) {
				c.add(Medium, "LS205", v, fmt.Sprintf("%q isn't a propagator the spec defines, so trace context won't be read or sent in that format.", item),
					"use names from: "+strings.Join(propagates, ", "))
			}
		}
	case strings.HasSuffix(n, "_COMPRESSION") && strings.HasPrefix(n, "OTEL_EXPORTER_OTLP"):
		if l := strings.ToLower(val); l != "gzip" && l != "none" {
			c.add(Medium, "LS206", v, fmt.Sprintf("%q isn't a supported compression. The spec allows gzip and none.", val), "use gzip or none")
		}
	case booleanVars[n]:
		if l := strings.ToLower(val); l != "true" && l != "false" {
			c.add(Medium, "LS602", v, fmt.Sprintf("Only \"true\" counts as true. The spec says %q must be read as false.", val), "use true or false")
		}
	case timeoutVars[n] || durationVars[n] || integerVars[n]:
		c.checkNumber(v, val)
	case strings.HasSuffix(n, "_HEADERS") && strings.HasPrefix(n, "OTEL_EXPORTER_OTLP"):
		c.checkPairs(v, val, true)
	case n == "OTEL_RESOURCE_ATTRIBUTES":
		c.checkPairs(v, val, false)
	}
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func (c *checker) checkNumber(v *envVar, val string) {
	num, err := strconv.ParseInt(val, 10, 64)
	if err != nil || num < 0 {
		what := "a whole number of milliseconds"
		if integerVars[v.Name] {
			what = "a whole number"
		}
		c.add(Medium, "LS402", v, fmt.Sprintf("%q isn't %s, so SDKs ignore it and use the default. Go logs a parse error and does the same.", val, what),
			"write "+what+", such as "+exampleNumber(v.Name))
		return
	}
	if timeoutVars[v.Name] && num > 0 && num < 100 {
		c.add(Medium, "LS401", v, fmt.Sprintf("This is %d milliseconds, not seconds. Any export slower than that is cancelled and counted as failed, so data is retried or dropped whenever the collector is slow or far away.", num),
			fmt.Sprintf("use %d for %d seconds", num*1000, num))
		return
	}
	if v.Name == "OTEL_METRIC_EXPORT_INTERVAL" && num > 0 && num < 1000 {
		c.add(Medium, "LS403", v, fmt.Sprintf("This is %d milliseconds, so metrics are exported %s per second.", num, perSecond(num)),
			fmt.Sprintf("use %d for %d seconds", num*1000, num))
	}
}

func perSecond(ms int64) string {
	n := (1000 + ms/2) / ms
	if 1000%ms == 0 {
		return strconv.FormatInt(n, 10) + " times"
	}
	return "about " + strconv.FormatInt(n, 10) + " times"
}

func exampleNumber(name string) string {
	if integerVars[name] {
		return "2048"
	}
	return "10000"
}

// checkPairs checks key=value lists: headers and resource attributes.
func (c *checker) checkPairs(v *envVar, val string, headers bool) {
	what := "resource attribute"
	if headers {
		what = "header"
	}
	semi, missing, escape := "LS504", "LS503", "LS505"
	if headers {
		semi, missing, escape = "LS502", "LS501", "LS505"
	}
	if strings.Contains(val, ";") {
		c.add(Medium, semi, v, fmt.Sprintf("Entries are separated by commas. With ;, the text after it becomes part of the previous %s's value, and the %ss after it are lost.", what, what),
			"separate entries with commas: key1=value1,key2=value2")
	}
	for _, p := range strings.Split(val, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if wholeRef.MatchString(p) {
			continue // a reference that expands to more entries, such as ${OTEL_RESOURCE_ATTRIBUTES}
		}
		k, rest, ok := strings.Cut(p, "=")
		if !ok || strings.TrimSpace(k) == "" {
			if headers {
				key, _, colon := strings.Cut(p, ":")
				how := "isn't key=value"
				if colon {
					how = "uses : instead of ="
				}
				c.add(High, missing, v, fmt.Sprintf("The %s entry %s, so SDKs can't read it. Go's SDK skips it and logs an error, so the request goes out without that header, and a backend that needs it rejects the data.", strings.TrimSpace(key), how),
					"write each header as key=value, for example Authorization=Bearer%20TOKEN")
			} else {
				c.add(Medium, missing, v, fmt.Sprintf("The entry %q isn't key=value. The spec says SDKs should then discard the whole variable; Go keeps the other attributes and reports an error.", clip(p, 60)),
					"write each attribute as key=value, separated by commas")
			}
			continue
		}
		if _, err := url.PathUnescape(k + rest); err != nil {
			c.add(Low, escape, v, fmt.Sprintf("A %s has a %% that isn't a valid percent-encoding, so SDKs can't decode it. Go keeps the raw text and logs an error.", what),
				"write %25 for a literal %")
		}
	}
}

var wholeRef = regexp.MustCompile(`^\$(\([A-Za-z_][A-Za-z0-9_]*\)|\{[A-Za-z_][A-Za-z0-9_]*(:?[-?+][^}]*)?\}|[A-Za-z_][A-Za-z0-9_]*)$`)

// endpoint describes one OTLP endpoint variable and how it will be used.
type endpoint struct {
	v        *envVar
	signals  []string // signals that use it
	proto    string   // explicit protocol for those signals, "" if unset or mixed
	generic  bool
	protoVar *envVar
}

func (c *checker) protocolFor(sig string) (string, *envVar) {
	for _, n := range []string{"OTEL_EXPORTER_OTLP_" + sig + "_PROTOCOL", "OTEL_EXPORTER_OTLP_PROTOCOL"} {
		if v := c.eff[n]; v != nil && v.Known && strings.TrimSpace(v.Value) != "" {
			p := strings.ToLower(strings.TrimSpace(v.Value))
			if !inList(p, protocols) {
				return "", nil // reported by LS201; read the endpoint as if unset
			}
			return p, v
		}
	}
	return "", nil
}

// usesOTLP says whether a signal may use the OTLP exporter.
func (c *checker) usesOTLP(sig string) bool {
	v := c.eff["OTEL_"+sig+"_EXPORTER"]
	if v == nil || !v.Known || strings.TrimSpace(v.Value) == "" {
		return true
	}
	for _, item := range splitList(v.Value) {
		if strings.HasPrefix(strings.ToLower(item), "otlp") {
			return true
		}
	}
	return false
}

func (c *checker) endpoints() []endpoint {
	var eps []endpoint
	var genericSignals []string
	for _, sig := range signals {
		if !c.usesOTLP(sig) {
			continue
		}
		if v := c.eff["OTEL_EXPORTER_OTLP_"+sig+"_ENDPOINT"]; v != nil && v.Known && strings.TrimSpace(v.Value) != "" {
			p, pv := c.protocolFor(sig)
			eps = append(eps, endpoint{v: v, signals: []string{sig}, proto: p, protoVar: pv})
			continue
		}
		genericSignals = append(genericSignals, sig)
	}
	if v := c.eff["OTEL_EXPORTER_OTLP_ENDPOINT"]; v != nil && v.Known && strings.TrimSpace(v.Value) != "" && len(genericSignals) > 0 {
		ep := endpoint{v: v, signals: genericSignals, generic: true}
		first := true
		for _, sig := range genericSignals {
			p, pv := c.protocolFor(sig)
			if first {
				ep.proto, ep.protoVar, first = p, pv, false
			} else if p != ep.proto {
				ep.proto, ep.protoVar = "mixed", nil
			}
		}
		eps = append(eps, ep)
	}
	return eps
}

func (c *checker) checkEndpoints() {
	for _, ep := range c.endpoints() {
		c.checkEndpoint(ep)
	}
}

func isHTTPProto(p string) bool { return strings.HasPrefix(p, "http/") }

func (c *checker) checkEndpoint(ep endpoint) {
	raw := strings.TrimSpace(ep.v.Value)
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		sev := High
		extra := ""
		if ep.proto == "grpc" {
			sev = Medium
			extra = " Some gRPC exporters accept host:port, but Go's doesn't."
		}
		c.add(sev, "LS104", ep.v, "This isn't a URL that starts with http:// or https://. Go's SDK can't parse it and sends to its default, https://localhost:4318, instead."+extra,
			"write the full URL, such as http://otel-collector:4318")
		return
	}
	port := u.Port()
	host := u.Hostname()
	p := strings.TrimSuffix(u.Path, "/")
	signalPath := ""
	for _, sig := range signals {
		if strings.HasSuffix(p, "/v1/"+lowerSignal(sig)) {
			signalPath = sig
		}
	}
	// With no protocol set, port 4317 suggests gRPC, unless the URL has an
	// OTLP/HTTP path, which only HTTP exporters use.
	httpLike := isHTTPProto(ep.proto) || (ep.proto == "" && (port != "4317" || signalPath != ""))
	if ep.proto == "mixed" {
		httpLike = false
	}
	if ep.proto == "" && port == "4317" && signalPath != "" {
		c.add(Medium, "LS105", ep.v, "The /v1/"+lowerSignal(signalPath)+" path is for OTLP/HTTP, but 4317 is the default OTLP/gRPC port. An HTTP exporter gets no answer it understands there.",
			"use port 4318 for OTLP/HTTP")
	}
	if ep.proto != "" && ep.proto != "mixed" && port != "" {
		if isHTTPProto(ep.proto) && port == "4317" {
			c.add(Medium, "LS105", ep.v, fmt.Sprintf("The protocol is %s, but 4317 is the default OTLP/gRPC port. A collector with default settings rejects HTTP requests there.", ep.proto),
				"use port 4318 for OTLP/HTTP, or set the protocol to grpc")
		}
		if ep.proto == "grpc" && port == "4318" {
			c.add(Medium, "LS105", ep.v, "The protocol is grpc, but 4318 is the default OTLP/HTTP port. A collector with default settings doesn't speak gRPC there.",
				"use port 4317 for gRPC, or set the protocol to http/protobuf")
		}
	}
	if port == "" && u.Scheme == "http" {
		c.add(Low, "LS106", ep.v, "The URL has no port, so it uses port 80. Collectors listen on 4318 for OTLP/HTTP and 4317 for gRPC by default.",
			"add the port, such as :4318, unless a proxy listens on port 80")
	}
	if isLocal(host) && !c.sc.LocalCollector && (c.sc.Platform == "kubernetes" || c.sc.Platform == "compose") {
		where := "pod"
		if c.sc.Platform == "compose" {
			where = "container"
		}
		c.add(Medium, "LS107", ep.v, fmt.Sprintf("%s here means this %s itself, and nothing else in it looks like a collector, so exports have nowhere to go.", host, where),
			"use the collector's service name, such as http://otel-collector:4318")
	}
	if !httpLike {
		return
	}
	if ep.generic {
		for _, sig := range signals {
			if strings.HasSuffix(p, "/v1/"+lowerSignal(sig)) {
				var dests []string
				for _, s := range ep.signals {
					dests = append(dests, fmt.Sprintf("%s to %s", lowerSignal(s), joinURL(u, "v1/"+lowerSignal(s))))
				}
				c.add(High, "LS101", ep.v, fmt.Sprintf("SDKs add /v1/<signal> to this base URL, so they send %s. The collector answers 404.", joinAnd(dests)),
					fmt.Sprintf("remove %s from the URL, or set OTEL_EXPORTER_OTLP_%s_ENDPOINT to this URL instead", "/v1/"+lowerSignal(sig), sig))
				return
			}
		}
		return
	}
	sig := ep.signals[0]
	if p == "" {
		c.add(High, "LS102", ep.v, fmt.Sprintf("SDKs use %s as written, with no path added, so %s go to %s/. The collector answers 404 there.", ep.v.Name, lowerSignal(sig), strings.TrimSuffix(raw, "/")),
			fmt.Sprintf("add the path: %s/v1/%s, or set OTEL_EXPORTER_OTLP_ENDPOINT instead, which gets the path added", strings.TrimSuffix(raw, "/"), lowerSignal(sig)))
		return
	}
	for _, other := range signals {
		if other != sig && strings.HasSuffix(p, "/v1/"+lowerSignal(other)) {
			c.add(High, "LS103", ep.v, fmt.Sprintf("This sends %s to the %s path. The collector rejects them there.", lowerSignal(sig), lowerSignal(other)),
				fmt.Sprintf("use the /v1/%s path", lowerSignal(sig)))
		}
	}
}

func joinAnd(items []string) string {
	if len(items) <= 1 {
		return strings.Join(items, "")
	}
	return strings.Join(items[:len(items)-1], ", ") + " and " + items[len(items)-1]
}

func joinURL(u *url.URL, rel string) string {
	cp := *u
	if !strings.HasSuffix(cp.Path, "/") {
		cp.Path += "/"
	}
	cp.Path += rel
	cp.User = nil
	return cp.String()
}

func isLocal(host string) bool {
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && (ip.IsLoopback() || ip.IsUnspecified())
}

func (c *checker) checkSampler() {
	s := c.eff["OTEL_TRACES_SAMPLER"]
	a := c.eff["OTEL_TRACES_SAMPLER_ARG"]
	sampler := ""
	if s != nil && s.Known {
		sampler = strings.ToLower(strings.TrimSpace(s.Value))
	}
	if s != nil && s.Known && (sampler == "always_off" || sampler == "parentbased_always_off") {
		c.add(Low, "LS304", s, "This sampler records no new traces"+map[bool]string{true: " unless a caller already sampled them.", false: "."}[sampler == "parentbased_always_off"],
			"remove it if tracing should be on")
	}
	if a == nil || !a.Known || strings.TrimSpace(a.Value) == "" {
		return
	}
	if s == nil {
		c.add(Medium, "LS303", a, "OTEL_TRACES_SAMPLER isn't set, so SDKs ignore this argument and sample every new trace.",
			"also set OTEL_TRACES_SAMPLER=parentbased_traceidratio")
		return
	}
	if !s.Known || (sampler != "traceidratio" && sampler != "parentbased_traceidratio") {
		return
	}
	val := strings.TrimSpace(a.Value)
	r, err := strconv.ParseFloat(val, 64)
	if err != nil || r < 0 || r > 1 {
		c.add(Medium, "LS302", a, fmt.Sprintf("%q isn't a ratio between 0 and 1. The spec says SDKs must then ignore it, which samples every trace; Go treats values above 1 as 1.", val),
			"write a fraction, such as 0.1 for 10%")
		return
	}
	if r == 0 && sampler == "traceidratio" {
		c.add(High, "LS301", a, "A ratio of 0 with traceidratio samples no traces at all.",
			"use a ratio above 0, such as 0.1")
	}
}

func (c *checker) checkBatchSizes() {
	for _, p := range []string{"OTEL_BSP_", "OTEL_BLRP_"} {
		q, b := c.eff[p+"MAX_QUEUE_SIZE"], c.eff[p+"MAX_EXPORT_BATCH_SIZE"]
		if q == nil || b == nil || !q.Known || !b.Known {
			continue
		}
		qn, err1 := strconv.Atoi(strings.TrimSpace(q.Value))
		bn, err2 := strconv.Atoi(strings.TrimSpace(b.Value))
		if err1 == nil && err2 == nil && bn > qn {
			c.add(Low, "LS404", b, fmt.Sprintf("The batch size (%d) is larger than the queue (%d). The spec says it must not be, so batches are never as large as set.", bn, qn),
				"make the batch size at most the queue size")
		}
	}
}
