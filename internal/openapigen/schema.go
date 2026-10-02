package openapigen

import (
	"go/types"
	"reflect"
	"sort"
	"strings"
	"unicode"
)

// schemas turns Go types into JSON Schema (OpenAPI 3.1) the way
// encoding/json serializes them. Named structs become components; request
// bodies get their own "…Input" components without required members (a
// handler's BodyParser accepts missing fields).
type schemas struct {
	components map[string]any
	names      map[string]string // type identity → component name
	owners     map[string]string // component name → type identity
}

func newSchemas() *schemas {
	return &schemas{components: map[string]any{}, names: map[string]string{}, owners: map[string]string{}}
}

const identityPkg = "github.com/Abraxas-365/iamkit/internal/identity"
const errxPkg = "github.com/Abraxas-365/iamkit/internal/errx"

func nullable(s map[string]any) map[string]any {
	if t, ok := s["type"].(string); ok {
		out := clone(s)
		out["type"] = []any{t, "null"}
		return out
	}
	if _, ok := s["$ref"]; ok {
		return map[string]any{"anyOf": []any{s, map[string]any{"type": "null"}}}
	}
	return s // anyValue already admits null
}

func clone(s map[string]any) map[string]any {
	out := make(map[string]any, len(s))
	for k, v := range s {
		out[k] = v
	}
	return out
}

// schema maps t; input selects the request flavor.
func (g *schemas) schema(t types.Type, input bool) map[string]any {
	if t == nil {
		return anyValue()
	}
	if named, ok := t.(*types.Named); ok {
		obj := named.Obj()
		if obj.Pkg() != nil {
			path, name := obj.Pkg().Path(), obj.Name()
			switch {
			case path == "time" && name == "Time":
				return map[string]any{"type": "string", "format": "date-time"}
			case path == "time" && name == "Duration":
				return map[string]any{"type": "integer"}
			case path == "encoding/json" && name == "RawMessage":
				return anyValue()
			case path == identityPkg && name == "ID":
				return map[string]any{"type": "string", "description": "UUID (empty when unset)"}
			case path == errxPkg && name == "Error":
				return ref("ErrorDetail")
			}
		}
		if has(t, "MarshalJSON") {
			return anyValue()
		}
		if has(t, "MarshalText") {
			return map[string]any{"type": "string"}
		}
		if st, ok := named.Underlying().(*types.Struct); ok {
			return g.component(named, st, input)
		}
		return g.schema(named.Underlying(), input)
	}
	if alias, ok := t.(*types.Alias); ok {
		return g.schema(types.Unalias(alias), input)
	}
	switch u := t.(type) {
	case *types.Basic:
		switch {
		case u.Info()&types.IsBoolean != 0:
			return map[string]any{"type": "boolean"}
		case u.Info()&types.IsInteger != 0:
			return map[string]any{"type": "integer"}
		case u.Info()&types.IsFloat != 0:
			return map[string]any{"type": "number"}
		case u.Info()&types.IsString != 0:
			return map[string]any{"type": "string"}
		}
		return anyValue()
	case *types.Pointer:
		return nullable(g.schema(u.Elem(), input))
	case *types.Slice:
		if b, ok := u.Elem().(*types.Basic); ok && b.Kind() == types.Byte {
			return map[string]any{"type": []any{"string", "null"}, "contentEncoding": "base64"}
		}
		return map[string]any{"type": []any{"array", "null"}, "items": g.schema(u.Elem(), input)}
	case *types.Array:
		return map[string]any{"type": "array", "items": g.schema(u.Elem(), input)}
	case *types.Map:
		return map[string]any{"type": []any{"object", "null"}, "additionalProperties": g.schema(u.Elem(), input)}
	case *types.Struct:
		return g.object(u, input)
	}
	return anyValue() // interfaces, any
}

// anyValue admits every JSON value, null included (kin-openapi reads a bare
// {} as non-nullable).
func anyValue() map[string]any {
	return map[string]any{"anyOf": []any{map[string]any{}, map[string]any{"type": "null"}}}
}

func ref(name string) map[string]any {
	return map[string]any{"$ref": "#/components/schemas/" + name}
}

func has(t types.Type, method string) bool {
	for _, candidate := range []types.Type{t, types.NewPointer(t)} {
		set := types.NewMethodSet(candidate)
		for i := 0; i < set.Len(); i++ {
			if set.At(i).Obj().Name() == method {
				return true
			}
		}
	}
	return false
}

func (g *schemas) component(named *types.Named, st *types.Struct, input bool) map[string]any {
	identity := types.TypeString(named, nil)
	if input {
		identity += "#input"
	}
	if name, ok := g.names[identity]; ok {
		return ref(name)
	}
	name := typeName(named, false)
	if input {
		name += "Input"
	}
	if owner, taken := g.owners[name]; taken && owner != identity {
		name = typeName(named, true)
		if input {
			name += "Input"
		}
		for i := 2; g.owners[name] != "" && g.owners[name] != identity; i++ {
			name = typeName(named, true) + string(rune('0'+i))
		}
	}
	g.names[identity], g.owners[name] = name, identity
	g.components[name] = map[string]any{} // placeholder: recursion ends at the $ref
	g.components[name] = g.object(st, input)
	return ref(name)
}

// typeName is the type's name with its type arguments (Paginated[User] →
// PaginatedUser), qualified by its package when two types share a name.
func typeName(named *types.Named, qualified bool) string {
	var b strings.Builder
	if qualified && named.Obj().Pkg() != nil {
		b.WriteString(title(strings.TrimSuffix(named.Obj().Pkg().Name(), "http")))
	}
	b.WriteString(title(named.Obj().Name()))
	if args := named.TypeArgs(); args != nil {
		for i := 0; i < args.Len(); i++ {
			b.WriteString(argName(args.At(i)))
		}
	}
	return b.String()
}

func argName(t types.Type) string {
	switch u := t.(type) {
	case *types.Named:
		return typeName(u, false)
	case *types.Pointer:
		return argName(u.Elem())
	case *types.Slice:
		return argName(u.Elem()) + "List"
	case *types.Basic:
		return title(u.Name())
	}
	return "Value"
}

func title(s string) string {
	if s == "" {
		return s
	}
	r := []rune(s)
	r[0] = unicode.ToUpper(r[0])
	return string(r)
}

type field struct {
	name     string
	schema   map[string]any
	required bool
}

func (g *schemas) object(st *types.Struct, input bool) map[string]any {
	props := map[string]any{}
	var required []string
	for _, f := range g.fields(st, input, false) {
		if _, dup := props[f.name]; dup {
			continue // the shallower field wins, like encoding/json
		}
		props[f.name] = f.schema
		if f.required && !input {
			required = append(required, f.name)
		}
	}
	out := map[string]any{"type": "object", "properties": props}
	if len(required) > 0 {
		sort.Strings(required)
		out["required"] = required
	}
	return out
}

func (g *schemas) fields(st *types.Struct, input, viaPointer bool) []field {
	var direct, promoted []field
	for i := 0; i < st.NumFields(); i++ {
		v := st.Field(i)
		tag := reflect.StructTag(st.Tag(i)).Get("json")
		if tag == "-" {
			continue
		}
		name, opts, _ := strings.Cut(tag, ",")
		omit := strings.Contains(opts, "omitempty") || strings.Contains(opts, "omitzero")
		if v.Embedded() && name == "" {
			inner := v.Type()
			pointer := false
			if p, ok := inner.(*types.Pointer); ok {
				inner, pointer = p.Elem(), true
			}
			if s, ok := inner.Underlying().(*types.Struct); ok && !has(inner, "MarshalJSON") {
				promoted = append(promoted, g.fields(s, input, viaPointer || pointer)...)
				continue
			}
		}
		if !v.Exported() {
			continue
		}
		if name == "" {
			name = v.Name()
		}
		switch v.Type().Underlying().(type) {
		case *types.Signature, *types.Chan:
			continue
		}
		s := g.schema(v.Type(), input)
		if strings.Contains(opts, "string") {
			s = map[string]any{"type": "string"}
		}
		direct = append(direct, field{name: name, schema: s, required: !omit && !viaPointer})
	}
	return append(direct, promoted...)
}
