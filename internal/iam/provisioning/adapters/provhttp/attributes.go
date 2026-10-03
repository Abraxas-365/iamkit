package provhttp

import (
	"encoding/json"
	"strings"
)

// project applies the `attributes` and `excludedAttributes` query parameters
// (RFC 7644 §3.4.2.5, §3.9) to one resource. Paths are case-insensitive, may be
// qualified with the core schema URN, may name an extension (or an attribute
// of it, `urn:…:enterprise:2.0:User:manager`) and may name one sub-attribute
// (`name.formatted`, `emails.value`). `id` and `schemas` are always returned;
// `attributes` wins when both are given.
func project(include, exclude, core string, resource any) any {
	if strings.TrimSpace(include) == "" && strings.TrimSpace(exclude) == "" {
		return resource
	}
	raw, err := json.Marshal(resource)
	if err != nil {
		return resource
	}
	var in map[string]any
	if err := json.Unmarshal(raw, &in); err != nil {
		return resource
	}
	var out map[string]any
	if strings.TrimSpace(include) != "" {
		out = map[string]any{}
		for _, key := range []string{"schemas", "id"} {
			if v, ok := in[key]; ok {
				out[key] = v
			}
		}
		for _, p := range attributePaths(include) {
			key, sub, ok := resolve(in, core, p)
			if !ok {
				continue
			}
			if sub == "" {
				out[key] = in[key]
				continue
			}
			if picked, ok := pick(in[key], sub); ok {
				out[key] = merge(out[key], picked)
			}
		}
	} else {
		out = in
		for _, p := range attributePaths(exclude) {
			key, sub, ok := resolve(in, core, p)
			if !ok || key == "id" || key == "schemas" {
				continue
			}
			if sub == "" {
				delete(out, key)
				continue
			}
			drop(out[key], sub)
		}
	}
	// An extension left out of the response is left out of schemas too.
	if schemas, ok := out["schemas"].([]any); ok {
		kept := schemas[:0:0]
		for _, s := range schemas {
			name, _ := s.(string)
			if _, present := out[name]; name == core || present {
				kept = append(kept, s)
			}
		}
		out["schemas"] = kept
	}
	return out
}

func attributePaths(list string) []string {
	var out []string
	for _, p := range strings.Split(list, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// resolve maps a requested path to the resource key it addresses and the
// sub-attribute below it ("" for the whole attribute).
func resolve(resource map[string]any, core, path string) (key, sub string, ok bool) {
	lower := strings.ToLower(path)
	if prefix := strings.ToLower(core) + ":"; strings.HasPrefix(lower, prefix) {
		path = path[len(prefix):]
		lower = lower[len(prefix):]
	} else {
		for k := range resource {
			if !strings.HasPrefix(k, "urn:") {
				continue
			}
			ext := strings.ToLower(k)
			if lower == ext {
				return k, "", true
			}
			if strings.HasPrefix(lower, ext+":") {
				return k, strings.ToLower(path[len(ext)+1:]), true
			}
		}
	}
	top, sub, _ := strings.Cut(lower, ".")
	for k := range resource {
		if strings.ToLower(k) == top {
			return k, sub, true
		}
	}
	return "", "", false
}

// pick keeps only sub (its first segment) of a complex value, or of every
// element of a multi-valued one.
func pick(value any, sub string) (any, bool) {
	first, _, _ := strings.Cut(sub, ".")
	field := func(m map[string]any) (map[string]any, bool) {
		for k, v := range m {
			if strings.ToLower(k) == first {
				return map[string]any{k: v}, true
			}
		}
		return nil, false
	}
	switch v := value.(type) {
	case map[string]any:
		m, ok := field(v)
		return m, ok
	case []any:
		list := []any{}
		for _, e := range v {
			if m, ok := e.(map[string]any); ok {
				if kept, ok := field(m); ok {
					list = append(list, kept)
				}
			}
		}
		return list, len(list) > 0
	}
	return nil, false
}

// merge combines two picks of the same attribute (`name.formatted,name.givenName`).
func merge(have, more any) any {
	switch m := more.(type) {
	case map[string]any:
		if h, ok := have.(map[string]any); ok {
			for k, v := range m {
				h[k] = v
			}
			return h
		}
	case []any:
		if h, ok := have.([]any); ok && len(h) == len(m) {
			for i := range h {
				merge(h[i], m[i])
			}
			return h
		}
	}
	return more
}

// drop removes sub (its first segment) from a complex value or every element
// of a multi-valued one.
func drop(value any, sub string) {
	first, _, _ := strings.Cut(sub, ".")
	strip := func(m map[string]any) {
		for k := range m {
			if strings.ToLower(k) == first {
				delete(m, k)
			}
		}
	}
	switch v := value.(type) {
	case map[string]any:
		strip(v)
	case []any:
		for _, e := range v {
			if m, ok := e.(map[string]any); ok {
				strip(m)
			}
		}
	}
}
