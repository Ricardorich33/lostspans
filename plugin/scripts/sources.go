package main

import (
	"fmt"
	pathpkg "path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// envVar is one OTEL_ setting in one scope.
type envVar struct {
	Name   string
	Value  string // after expansion; meaningful only when Known
	Known  bool   // the value is a literal, or expanded from literals
	Why    string // why the value isn't known
	File   string
	Line   int
	Origin string // where it was set, such as "env" or "envFrom ConfigMap otel"
}

// scope is the environment of one program: a container, a Compose service or an env file.
type scope struct {
	Label    string // "Deployment api, container app"
	File     string
	Line     int
	Vars     []*envVar // OTEL_ variables in the order they're set; later ones win
	Platform string    // "kubernetes", "compose", "envfile" or "configmap"
	Mounts   []string  // absolute volumeMount mountPaths in this container
	// LocalCollector is true when something in the same network namespace
	// may listen on the OTLP ports, so localhost endpoints can work.
	LocalCollector bool
	Unread         []string // sources of variables that couldn't be read
	configMap      *Node    // set for a ConfigMap's own scope
}

// effective returns the winning definition of each name.
func (s *scope) effective() map[string]*envVar {
	m := map[string]*envVar{}
	for _, v := range s.Vars {
		m[v.Name] = v
	}
	return m
}

// inventory is everything read from the inputs.
type inventory struct {
	Files      int
	Objects    int
	Scopes     []*scope
	Skipped    []skipped
	configMaps map[string]*Node // "namespace/name" and "/name"
	cmFiles    map[*Node]string
	referenced map[*Node]bool // ConfigMaps loaded by a container in the inputs
	lastLine   map[string]int // last content line of each file
}

const otelPrefix = "OTEL_"

// load turns the sources into scopes, or returns an untrusted error.
func load(srcs []source) (*inventory, error) {
	inv := &inventory{configMaps: map[string]*Node{}, cmFiles: map[*Node]string{}, referenced: map[*Node]bool{}, lastLine: map[string]int{}}
	type k8sDoc struct {
		file string
		obj  *Node
	}
	var objs []k8sDoc
	type composeDoc struct {
		file string
		doc  *Node
	}
	var composes []composeDoc
	for _, s := range srcs {
		base := filepath.Base(s.name)
		if s.name != "<stdin>" && isEnvFileName(base) {
			if err := checkBytes(s.name, s.data); err != nil {
				return nil, err
			}
			vars, err := parseDotenv(s.name, s.data, nil)
			if err != nil {
				return nil, err
			}
			inv.Files++
			sc := &scope{Label: "env file", File: s.name, Line: 1, Platform: "envfile", LocalCollector: true}
			for _, v := range vars {
				if strings.HasPrefix(v.Name, otelPrefix) {
					v.Origin = "env file"
					sc.Vars = append(sc.Vars, v)
				}
			}
			inv.Scopes = append(inv.Scopes, sc)
			continue
		}
		if !s.explicit {
			// In a directory walk, leave unrendered templates and other YAML alone,
			// but never a file that looks like a manifest and can't be read.
			if isHelmTemplate(s.data) {
				inv.Skipped = append(inv.Skipped, skipped{s.name, "unrendered template"})
				continue
			}
		}
		if err := checkBytes(s.name, s.data); err != nil {
			return nil, err
		}
		if isHelmTemplate(s.data) {
			return nil, untrusted{s.name, "this is an unrendered template. Render it first, for example with helm template"}
		}
		docs, err := yamlDocs(s.name, s.data)
		if err != nil {
			return nil, err
		}
		if len(docs) == 0 {
			if !s.explicit {
				inv.Skipped = append(inv.Skipped, skipped{s.name, "only comments"})
				continue
			}
			return nil, untrusted{s.name, "the file has only comments or empty documents"}
		}
		inv.lastLine[s.name] = lastContentLine(s.data)
		recognized, other := 0, 0
		for _, d := range docs {
			switch {
			case d.Kind == MappingNode && mapGet(d, "kind") != nil && mapGet(d, "apiVersion") != nil:
				recognized++
				items, err := k8sObjects(s.name, d)
				if err != nil {
					return nil, err
				}
				for _, o := range items {
					objs = append(objs, k8sDoc{s.name, o})
				}
			case d.Kind == MappingNode && mapGet(d, "services") != nil && mapGet(d, "kind") == nil:
				recognized++
				composes = append(composes, composeDoc{s.name, d})
			default:
				other++
			}
		}
		if other > 0 {
			if !s.explicit && recognized == 0 && !anyText(docs) {
				inv.Skipped = append(inv.Skipped, skipped{s.name, "not a manifest, Compose file or env file"})
				continue
			}
			return nil, untrusted{s.name, describeOther(docs)}
		}
		inv.Files++
	}
	for _, o := range objs {
		inv.Objects++
		if k, _ := scalar(mapGet(o.obj, "kind")); k == "ConfigMap" {
			name, _ := scalar(path(o.obj, "metadata", "name"))
			ns, _ := scalar(path(o.obj, "metadata", "namespace"))
			inv.configMaps[ns+"/"+name] = o.obj
			inv.configMaps["/"+name] = o.obj
			inv.cmFiles[o.obj] = o.file
		}
	}
	for _, o := range objs {
		sc, err := k8sScopes(inv, o.file, o.obj)
		if err != nil {
			return nil, err
		}
		inv.Scopes = append(inv.Scopes, sc...)
	}
	kept := inv.Scopes[:0]
	for _, sc := range inv.Scopes {
		if sc.configMap == nil || !inv.referenced[sc.configMap] {
			kept = append(kept, sc)
		}
	}
	inv.Scopes = kept
	for _, c := range composes {
		sc, err := composeScopes(c.file, c.doc)
		if err != nil {
			return nil, err
		}
		inv.Objects += len(sc)
		inv.Scopes = append(inv.Scopes, sc...)
	}
	return inv, nil
}

var helmMarker = regexp.MustCompile(`\{\{-?\s*(\.Values|\.Release|\.Chart|\.Capabilities|\.Files|include\s|template\s|toYaml|if\s|range\s|with\s|end\s*-?\}\}|define\s)`)

// isHelmTemplate spots Helm template syntax. Rendered manifests can still hold
// {{ $labels.x }} in alert templates, which isn't Helm's.
func isHelmTemplate(data []byte) bool {
	return helmMarker.Match(data)
}

func firstKey(d *Node) string {
	for i := 0; i < len(d.Content); i += 2 {
		if strings.Count(d.Content[i].Value, " ") >= 2 {
			return d.Content[i].Value
		}
	}
	return ""
}

// anyText says whether a document is prose rather than config: a bare string,
// or a mapping whose key is a sentence, as when an error message is read as YAML.
func anyText(docs []*Node) bool {
	for _, d := range docs {
		if d.Kind == ScalarNode {
			return true
		}
		if d.Kind == MappingNode {
			for i := 0; i < len(d.Content); i += 2 {
				if strings.Count(d.Content[i].Value, " ") >= 2 {
					return true
				}
			}
		}
	}
	return false
}

func describeOther(docs []*Node) string {
	for _, d := range docs {
		if d.Kind == ScalarNode {
			return fmt.Sprintf("line %d is plain text, not a Kubernetes object, Compose file or env file: %q", d.Line, clip(d.Value, 120))
		}
		if d.Kind == MappingNode && anyText([]*Node{d}) {
			return fmt.Sprintf("line %d is text, not a Kubernetes object, Compose file or env file: %q", d.Line, clip(firstKey(d), 120))
		}
		if d.Kind == MappingNode && mapGet(d, "kind") == nil {
			return fmt.Sprintf("the document at line %d isn't a Kubernetes object (no kind and apiVersion) or a Compose file (no services)", d.Line)
		}
		if d.Kind == MappingNode {
			return fmt.Sprintf("the document at line %d has a kind but no apiVersion", d.Line)
		}
		if d.Kind == SequenceNode {
			return fmt.Sprintf("the document at line %d is a list, not a Kubernetes object or Compose file", d.Line)
		}
	}
	return "not a Kubernetes object, Compose file or env file"
}

// k8sObjects validates an object and unpacks kind: List.
func k8sObjects(file string, d *Node) ([]*Node, error) {
	kind, ok := scalar(mapGet(d, "kind"))
	if !ok || kind == "" {
		return nil, untrusted{file, fmt.Sprintf("the object at line %d has no kind", d.Line)}
	}
	if av, ok := scalar(mapGet(d, "apiVersion")); !ok || av == "" {
		return nil, untrusted{file, fmt.Sprintf("the object at line %d has no apiVersion", d.Line)}
	}
	if kind == "Status" {
		msg, _ := scalar(mapGet(d, "message"))
		return nil, untrusted{file, "this is a Kubernetes API error, not an object: " + clip(msg, 160)}
	}
	if strings.HasSuffix(kind, "List") && mapGet(d, "items") != nil {
		items := mapGet(d, "items")
		if items.Kind != SequenceNode {
			return nil, untrusted{file, fmt.Sprintf("the %s at line %d has items that aren't a list", kind, d.Line)}
		}
		if len(items.Content) == 0 {
			return nil, untrusted{file, fmt.Sprintf("the %s at line %d is empty", kind, d.Line)}
		}
		var out []*Node
		for _, it := range items.Content {
			if it.Kind != MappingNode {
				return nil, untrusted{file, fmt.Sprintf("item at line %d isn't an object", it.Line)}
			}
			sub, err := k8sObjects(file, it)
			if err != nil {
				return nil, err
			}
			out = append(out, sub...)
		}
		return out, nil
	}
	name, _ := scalar(path(d, "metadata", "name"))
	gen, _ := scalar(path(d, "metadata", "generateName"))
	if name == "" && gen == "" {
		return nil, untrusted{file, fmt.Sprintf("the %s at line %d has no metadata.name", kind, d.Line)}
	}
	return []*Node{d}, nil
}

// podSpecPaths are where known workload kinds keep their pod spec.
var podSpecPaths = map[string][]string{
	"Pod":                   {"spec"},
	"Deployment":            {"spec", "template", "spec"},
	"StatefulSet":           {"spec", "template", "spec"},
	"DaemonSet":             {"spec", "template", "spec"},
	"ReplicaSet":            {"spec", "template", "spec"},
	"ReplicationController": {"spec", "template", "spec"},
	"Job":                   {"spec", "template", "spec"},
	"CronJob":               {"spec", "jobTemplate", "spec", "template", "spec"},
	"PodTemplate":           {"template", "spec"},
}

func k8sScopes(inv *inventory, file string, obj *Node) ([]*scope, error) {
	kind, _ := scalar(mapGet(obj, "kind"))
	name, _ := scalar(path(obj, "metadata", "name"))
	if name == "" {
		name, _ = scalar(path(obj, "metadata", "generateName"))
	}
	ns, _ := scalar(path(obj, "metadata", "namespace"))
	var spec *Node
	if p, ok := podSpecPaths[kind]; ok {
		spec = path(obj, p...)
		if spec == nil || spec.Kind != MappingNode {
			return nil, untrusted{file, fmt.Sprintf("%s %s at line %d has no pod spec at %s, so it may be cut off", kind, name, obj.Line, strings.Join(p, "."))}
		}
	} else if s := path(obj, "spec", "template", "spec"); s != nil && mapGet(s, "containers") != nil {
		spec = s
	} else {
		if kind == "ConfigMap" {
			return configMapScope(file, obj, name)
		}
		return nil, nil
	}
	containers := mapGet(spec, "containers")
	if containers == nil || containers.Kind != SequenceNode || len(containers.Content) == 0 {
		return nil, untrusted{file, fmt.Sprintf("%s %s at line %d has no containers, so it may be cut off", kind, name, obj.Line)}
	}
	if kind == "Job" || kind == "CronJob" {
		if rp, _ := scalar(mapGet(spec, "restartPolicy")); rp != "Never" && rp != "OnFailure" {
			return nil, untrusted{file, fmt.Sprintf("%s %s at line %d has no restartPolicy of Never or OnFailure, which Kubernetes requires, so it may be cut off", kind, name, obj.Line)}
		}
	}
	hostNet, _ := scalar(mapGet(spec, "hostNetwork"))
	type ctr struct {
		node *Node
		init bool
	}
	var all []ctr
	for _, c := range containers.Content {
		all = append(all, ctr{c, false})
	}
	if ic := mapGet(spec, "initContainers"); ic != nil {
		if ic.Kind != SequenceNode {
			return nil, untrusted{file, fmt.Sprintf("%s %s: initContainers at line %d isn't a list", kind, name, ic.Line)}
		}
		for _, c := range ic.Content {
			all = append(all, ctr{c, true})
		}
	}
	for _, c := range all {
		if c.node.Kind != MappingNode {
			return nil, untrusted{file, fmt.Sprintf("%s %s: container at line %d isn't an object", kind, name, c.node.Line)}
		}
		cn, _ := scalar(mapGet(c.node, "name"))
		img, _ := scalar(mapGet(c.node, "image"))
		if cn == "" || img == "" {
			return nil, untrusted{file, fmt.Sprintf("%s %s: the container at line %d has no name or no image, so it may be cut off", kind, name, c.node.Line)}
		}
	}
	var out []*scope
	for i, c := range all {
		cn, _ := scalar(mapGet(c.node, "name"))
		label := fmt.Sprintf("%s %s, container %s", kind, name, cn)
		if c.init {
			label = fmt.Sprintf("%s %s, init container %s", kind, name, cn)
		}
		sc := &scope{Label: label, File: file, Line: c.node.Line, Platform: "kubernetes"}
		if hostNet == "true" {
			sc.LocalCollector = true
		}
		mounts, err := containerMounts(file, label, c.node)
		if err != nil {
			return nil, err
		}
		sc.Mounts = mounts
		for j, o := range all {
			if j != i && looksLikeCollector(o.node) {
				sc.LocalCollector = true
			}
		}
		if err := containerEnv(inv, file, ns, label, c.node, sc); err != nil {
			return nil, err
		}
		out = append(out, sc)
	}
	return out, nil
}

// containerMounts returns the absolute mountPath values for one container.
// Only these paths can make a file from a volume visible inside the container.
func containerMounts(file, label string, c *Node) ([]string, error) {
	mounts := mapGet(c, "volumeMounts")
	if mounts == nil || (mounts.Kind == ScalarNode && mounts.Tag == "!!null") {
		return nil, nil
	}
	if mounts.Kind != SequenceNode {
		return nil, untrusted{file, fmt.Sprintf("%s: volumeMounts at line %d isn't a list", label, mounts.Line)}
	}
	var out []string
	for _, m := range mounts.Content {
		if m.Kind != MappingNode {
			return nil, untrusted{file, fmt.Sprintf("%s: volumeMount at line %d isn't an object", label, m.Line)}
		}
		mountPath, ok := scalar(mapGet(m, "mountPath"))
		if !ok {
			return nil, untrusted{file, fmt.Sprintf("%s: volumeMount at line %d has no mountPath", label, m.Line)}
		}
		mountPath = strings.TrimSpace(mountPath)
		if mountPath == "" {
			return nil, untrusted{file, fmt.Sprintf("%s: volumeMount at line %d has no mountPath", label, m.Line)}
		}
		if strings.HasPrefix(mountPath, "/") {
			out = append(out, pathpkg.Clean(mountPath))
		}
	}
	return out, nil
}

// configMapScope checks OTEL_ keys in a ConfigMap on their own. Containers that
// load the ConfigMap with envFrom check them again in context.
func configMapScope(file string, obj *Node, name string) ([]*scope, error) {
	data := mapGet(obj, "data")
	if data == nil {
		return nil, nil
	}
	if data.Kind != MappingNode {
		return nil, untrusted{file, fmt.Sprintf("ConfigMap %s: data at line %d isn't a map", name, data.Line)}
	}
	sc := &scope{Label: "ConfigMap " + name, File: file, Line: obj.Line, Platform: "configmap", LocalCollector: true, configMap: obj}
	for i := 0; i+1 < len(data.Content); i += 2 {
		k := data.Content[i].Value
		if !strings.HasPrefix(k, otelPrefix) {
			continue
		}
		v, ok := scalar(data.Content[i+1])
		sc.Vars = append(sc.Vars, &envVar{Name: k, Value: v, Known: ok || data.Content[i+1].Tag == "!!null", File: file, Line: data.Content[i].Line, Origin: "ConfigMap " + name})
	}
	if len(sc.Vars) == 0 {
		return nil, nil
	}
	return []*scope{sc}, nil
}

var collectorImage = regexp.MustCompile(`(?i)(otel|opentelemetry|collector|alloy|datadog|agent|jaeger|tempo|signoz|elastic-agent|honeycomb|newrelic|splunk)`)

// looksLikeCollector reports whether a container in the same pod may receive OTLP on localhost.
func looksLikeCollector(c *Node) bool {
	img, _ := scalar(mapGet(c, "image"))
	if collectorImage.MatchString(img) {
		return true
	}
	if ports := mapGet(c, "ports"); ports != nil {
		for _, p := range ports.Content {
			if v, _ := scalar(mapGet(p, "containerPort")); v == "4317" || v == "4318" {
				return true
			}
		}
	}
	return false
}

// containerEnv collects envFrom and env, expanding $(VAR) the way kubelet does.
func containerEnv(inv *inventory, file, ns, label string, c *Node, sc *scope) error {
	known := map[string]*envVar{} // every variable set so far, OTEL_ or not
	if ef := mapGet(c, "envFrom"); ef != nil {
		if ef.Kind != SequenceNode {
			return untrusted{file, fmt.Sprintf("%s: envFrom at line %d isn't a list", label, ef.Line)}
		}
		for _, e := range ef.Content {
			prefix, _ := scalar(mapGet(e, "prefix"))
			if ref := mapGet(e, "configMapRef"); ref != nil {
				name, _ := scalar(mapGet(ref, "name"))
				cm := inv.configMaps[ns+"/"+name]
				if cm == nil {
					cm = inv.configMaps["/"+name]
				}
				if cm == nil {
					sc.Unread = append(sc.Unread, "ConfigMap "+name)
					continue
				}
				inv.referenced[cm] = true
				data := mapGet(cm, "data")
				if data == nil || data.Kind != MappingNode {
					continue
				}
				for i := 0; i+1 < len(data.Content); i += 2 {
					k := prefix + data.Content[i].Value
					v, _ := scalar(data.Content[i+1])
					ev := &envVar{Name: k, Value: v, Known: true, File: inv.cmFiles[cm], Line: data.Content[i].Line, Origin: "envFrom ConfigMap " + name}
					known[k] = ev
					if strings.HasPrefix(k, otelPrefix) {
						sc.Vars = append(sc.Vars, ev)
					}
				}
			}
			if ref := mapGet(e, "secretRef"); ref != nil {
				name, _ := scalar(mapGet(ref, "name"))
				sc.Unread = append(sc.Unread, "Secret "+name)
			}
		}
	}
	env := mapGet(c, "env")
	if env == nil {
		return nil
	}
	if env.Kind != SequenceNode {
		return untrusted{file, fmt.Sprintf("%s: env at line %d isn't a list", label, env.Line)}
	}
	for _, e := range env.Content {
		if e.Kind != MappingNode {
			return untrusted{file, fmt.Sprintf("%s: env entry at line %d isn't an object", label, e.Line)}
		}
		name, _ := scalar(mapGet(e, "name"))
		if name == "" {
			return untrusted{file, fmt.Sprintf("%s: env entry at line %d has no name", label, e.Line)}
		}
		ev := &envVar{Name: name, File: file, Line: e.Line, Origin: "env"}
		if vf := mapGet(e, "valueFrom"); vf != nil {
			ev.Why = "set from valueFrom"
		} else if vn := mapGet(e, "value"); vn != nil {
			if vn.Kind != ScalarNode {
				return untrusted{file, fmt.Sprintf("%s: the value of %s at line %d isn't a string", label, name, vn.Line)}
			}
			raw, _ := scalar(vn)
			val, ok, why := kubeExpand(raw, known)
			ev.Value, ev.Known, ev.Why = val, ok, why
		} else {
			if e.Line == inv.lastLine[file] {
				return untrusted{file, fmt.Sprintf("%s: the env entry %s on the last line has no value, so the file may be cut off", label, name)}
			}
			ev.Known = true // no value means an empty string
		}
		known[name] = ev
		if strings.HasPrefix(name, otelPrefix) {
			sc.Vars = append(sc.Vars, ev)
		}
	}
	return nil
}

// kubeExpand expands $(NAME) from variables set earlier in the container, as
// kubelet does. $$ is a literal $. A reference kubelet can't resolve stays as
// written; one to a variable whose value isn't known makes the result unknown.
func kubeExpand(s string, known map[string]*envVar) (string, bool, string) {
	var b strings.Builder
	ok, why := true, ""
	for i := 0; i < len(s); i++ {
		if s[i] != '$' || i+1 >= len(s) {
			b.WriteByte(s[i])
			continue
		}
		switch s[i+1] {
		case '$':
			b.WriteByte('$')
			i++
		case '(':
			end := strings.IndexByte(s[i+2:], ')')
			if end < 0 {
				b.WriteString(s[i:])
				return b.String(), ok, why
			}
			name := s[i+2 : i+2+end]
			ref, found := known[name]
			switch {
			case !found:
				b.WriteString("$(" + name + ")")
			case !ref.Known:
				ok, why = false, "uses $("+name+"), which is "+strings.TrimPrefix(ref.Why, "uses ")
				b.WriteString("$(" + name + ")")
			default:
				b.WriteString(ref.Value)
			}
			i += 2 + end
		default:
			b.WriteByte('$')
		}
	}
	return b.String(), ok, why
}

// composeScopes reads services from a Compose file, interpolating ${VAR}
// from the .env file next to it, never from the shell.
func composeScopes(file string, doc *Node) ([]*scope, error) {
	services := mapGet(doc, "services")
	if services.Kind != MappingNode || len(services.Content) == 0 {
		return nil, untrusted{file, fmt.Sprintf("services at line %d is empty or isn't a map", services.Line)}
	}
	dir := filepath.Dir(file)
	dotenv := map[string]*envVar{}
	if file != "<stdin>" {
		if data, err := readFileIfExists(filepath.Join(dir, ".env")); err != nil {
			return nil, err
		} else if data != nil {
			if err := checkBytes(filepath.Join(dir, ".env"), data); err != nil {
				return nil, err
			}
			vars, err := parseDotenv(filepath.Join(dir, ".env"), data, nil)
			if err != nil {
				return nil, err
			}
			for _, v := range vars {
				dotenv[v.Name] = v
			}
		}
	}
	type svc struct {
		name string
		node *Node
	}
	var list []svc
	for i := 0; i+1 < len(services.Content); i += 2 {
		list = append(list, svc{services.Content[i].Value, services.Content[i+1]})
	}
	collectors := map[string]bool{}
	for _, s := range list {
		if s.node.Kind != MappingNode {
			return nil, untrusted{file, fmt.Sprintf("service %s at line %d isn't a map", s.name, s.node.Line)}
		}
		if looksLikeCollector(s.node) {
			collectors[s.name] = true
		}
	}
	var out []*scope
	for _, s := range list {
		sc := &scope{Label: "Compose service " + s.name, File: file, Line: s.node.Line, Platform: "compose"}
		nm, _ := scalar(mapGet(s.node, "network_mode"))
		nm = composeInterp(nm, dotenv)
		if nm == "host" || strings.HasPrefix(nm, "container:") || (strings.HasPrefix(nm, "service:") && collectors[strings.TrimPrefix(nm, "service:")]) {
			sc.LocalCollector = true
		}
		if ef := mapGet(s.node, "env_file"); ef != nil {
			var paths []struct {
				p        string
				required bool
			}
			add := func(n *Node) {
				if v, ok := scalar(n); ok {
					paths = append(paths, struct {
						p        string
						required bool
					}{v, true})
				} else if n.Kind == MappingNode {
					p, _ := scalar(mapGet(n, "path"))
					req, _ := scalar(mapGet(n, "required"))
					paths = append(paths, struct {
						p        string
						required bool
					}{p, req != "false"})
				}
			}
			if ef.Kind == SequenceNode {
				for _, n := range ef.Content {
					add(n)
				}
			} else {
				add(ef)
			}
			for _, p := range paths {
				full := composeInterp(p.p, dotenv)
				if !filepath.IsAbs(full) {
					full = filepath.Join(dir, full)
				}
				data, err := readFileIfExists(full)
				if err != nil {
					return nil, err
				}
				if data == nil {
					if p.required {
						return nil, untrusted{file, fmt.Sprintf("service %s: env_file %s doesn't exist, and Compose won't start without it", s.name, p.p)}
					}
					continue
				}
				if err := checkBytes(full, data); err != nil {
					return nil, err
				}
				vars, err := parseDotenv(full, data, dotenv)
				if err != nil {
					return nil, err
				}
				for _, v := range vars {
					if strings.HasPrefix(v.Name, otelPrefix) {
						v.Origin = "env_file " + p.p
						sc.Vars = append(sc.Vars, v)
					}
				}
			}
		}
		if env := mapGet(s.node, "environment"); env != nil {
			switch env.Kind {
			case MappingNode:
				for i := 0; i+1 < len(env.Content); i += 2 {
					k := env.Content[i].Value
					if !strings.HasPrefix(k, otelPrefix) {
						continue
					}
					ev := &envVar{Name: k, File: file, Line: env.Content[i].Line, Origin: "environment"}
					if v, ok := scalar(env.Content[i+1]); ok {
						ev.Value, ev.Known, ev.Why = composeExpand(v, dotenv)
					} else {
						passThrough(ev, dotenv)
					}
					sc.Vars = append(sc.Vars, ev)
				}
			case SequenceNode:
				for _, it := range env.Content {
					item, ok := scalar(it)
					if !ok {
						return nil, untrusted{file, fmt.Sprintf("service %s: environment entry at line %d isn't a string", s.name, it.Line)}
					}
					k, v, hasEq := strings.Cut(item, "=")
					if !strings.HasPrefix(k, otelPrefix) {
						continue
					}
					ev := &envVar{Name: k, File: file, Line: it.Line, Origin: "environment"}
					if hasEq {
						ev.Value, ev.Known, ev.Why = composeExpand(v, dotenv)
					} else {
						passThrough(ev, dotenv)
					}
					sc.Vars = append(sc.Vars, ev)
				}
			default:
				return nil, untrusted{file, fmt.Sprintf("service %s: environment at line %d isn't a map or list", s.name, env.Line)}
			}
		}
		out = append(out, sc)
	}
	return out, nil
}

// passThrough resolves a Compose variable listed without a value. Compose takes
// it from the shell, or from the .env file when the shell doesn't set it.
func passThrough(ev *envVar, dotenv map[string]*envVar) {
	if d, ok := dotenv[ev.Name]; ok && d.Known {
		ev.Value, ev.Known = d.Value, true
		ev.Origin = "environment, value from .env"
		return
	}
	ev.Why = "taken from the shell that runs Compose"
}

var composeRef = regexp.MustCompile(`\$\$|\$\{([A-Za-z_][A-Za-z0-9_]*)((:?[-?+])([^}]*))?\}|\$([A-Za-z_][A-Za-z0-9_]*)`)

// composeExpand interpolates like Compose, using only the .env file.
func composeExpand(s string, vars map[string]*envVar) (string, bool, string) {
	ok, why := true, ""
	out := composeRef.ReplaceAllStringFunc(s, func(m string) string {
		if m == "$$" {
			return "$"
		}
		sub := composeRef.FindStringSubmatch(m)
		name := sub[1]
		if name == "" {
			name = sub[5]
		}
		op, def := sub[3], sub[4]
		v, found := vars[name]
		set := found && v.Known
		empty := set && v.Value == ""
		switch op {
		case ":-":
			if !set || empty {
				if found && !v.Known {
					ok, why = false, "uses ${"+name+"}, which is "+v.Why
				}
				return def
			}
		case "-":
			if !found {
				return def
			}
		case ":+", "+":
			if set && (op == "+" || !empty) {
				return def
			}
			return ""
		}
		if !found {
			ok, why = false, "uses ${"+name+"}, which comes from the shell that runs Compose"
			return m
		}
		if !v.Known {
			ok, why = false, "uses ${"+name+"}, which is "+v.Why
			return m
		}
		return v.Value
	})
	return out, ok, why
}

func composeInterp(s string, vars map[string]*envVar) string {
	v, _, _ := composeExpand(s, vars)
	return v
}

var dotenvKey = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.\-]*$`)

// parseDotenv reads KEY=VALUE lines. Values can use ${VAR} from earlier lines
// and from base. Any other line makes the file untrusted.
func parseDotenv(file string, data []byte, base map[string]*envVar) ([]*envVar, error) {
	vars := map[string]*envVar{}
	for k, v := range base {
		vars[k] = v
	}
	var out []*envVar
	for i, line := range strings.Split(string(data), "\n") {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		t = strings.TrimPrefix(t, "export ")
		k, v, ok := strings.Cut(t, "=")
		k = strings.TrimSpace(k)
		if !ok || !dotenvKey.MatchString(k) {
			return nil, untrusted{file, fmt.Sprintf("line %d isn't KEY=VALUE: %q", i+1, clip(t, 120))}
		}
		v = strings.TrimSpace(v)
		ev := &envVar{Name: k, File: file, Line: i + 1, Known: true}
		switch {
		case len(v) >= 2 && v[0] == '\'' && v[len(v)-1] == '\'':
			ev.Value = v[1 : len(v)-1]
		case len(v) >= 1 && v[0] == '\'':
			return nil, untrusted{file, fmt.Sprintf("line %d has an unclosed quote", i+1)}
		case len(v) >= 2 && v[0] == '"' && v[len(v)-1] == '"':
			ev.Value, ev.Known, ev.Why = composeExpand(v[1:len(v)-1], vars)
		case len(v) >= 1 && v[0] == '"':
			return nil, untrusted{file, fmt.Sprintf("line %d has an unclosed quote", i+1)}
		default:
			if j := strings.Index(v, " #"); j >= 0 {
				v = strings.TrimSpace(v[:j])
			}
			ev.Value, ev.Known, ev.Why = composeExpand(v, vars)
		}
		vars[k] = ev
		out = append(out, ev)
	}
	if len(out) == 0 {
		return nil, untrusted{file, "the env file has no KEY=VALUE lines"}
	}
	return out, nil
}

func sortedKeys(m map[string]*envVar) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
