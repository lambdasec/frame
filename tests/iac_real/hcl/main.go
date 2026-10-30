// For every directory of .tf files: every attribute's value as HCL evaluates it, with the
// variables Terraform would load by itself (default, terraform.tfvars, *.auto.tfvars), locals
// evaluated to a fixpoint, and every resource, data source, module and meta value unknown.
// One JSON line per attribute: {"file", "line", "path", "value"} or {"file", "line", "path", "error": true}.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/ext/typeexpr"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/convert"
	"github.com/zclconf/go-cty/cty/function"
	"github.com/zclconf/go-cty/cty/function/stdlib"
)

var known = map[string]function.Function{
	"jsonencode": stdlib.JSONEncodeFunc, "jsondecode": stdlib.JSONDecodeFunc,
	"lower": stdlib.LowerFunc, "upper": stdlib.UpperFunc, "concat": stdlib.ConcatFunc,
	"merge": stdlib.MergeFunc,
	"contains": stdlib.ContainsFunc, "compact": stdlib.CompactFunc,
	"flatten": stdlib.FlattenFunc, "join": stdlib.JoinFunc, "split": stdlib.SplitFunc,
	"keys": stdlib.KeysFunc, "values": stdlib.ValuesFunc, "element": stdlib.ElementFunc,
}

// Terraform's own functions (internal/lang/funcs), with the same semantics.

// tostring, tonumber, tobool, tolist: a conversion to that type.
func convFunc(want cty.Type) function.Function {
	return function.New(&function.Spec{
		Params: []function.Parameter{{Name: "v", Type: cty.DynamicPseudoType, AllowNull: true,
			AllowDynamicType: true, AllowUnknown: true}},
		Type: func(args []cty.Value) (cty.Type, error) {
			if args[0].Type().Equals(want) {
				return want, nil
			}
			if convert.GetConversionUnsafe(args[0].Type(), want) == nil {
				return cty.NilType, fmt.Errorf("cannot convert")
			}
			return want, nil
		},
		Impl: func(args []cty.Value, retType cty.Type) (cty.Value, error) {
			if !args[0].IsKnown() {
				return cty.UnknownVal(retType), nil
			}
			return convert.Convert(args[0], retType)
		},
	})
}

// coalesce: the first argument that is neither null nor (for strings) empty.
var coalesceFunc = function.New(&function.Spec{
	VarParam: &function.Parameter{Name: "vals", Type: cty.DynamicPseudoType, AllowUnknown: true,
		AllowDynamicType: true, AllowNull: true},
	Type: func(args []cty.Value) (cty.Type, error) {
		tys := make([]cty.Type, len(args))
		for i, a := range args {
			tys[i] = a.Type()
		}
		ret, _ := convert.UnifyUnsafe(tys)
		if ret == cty.NilType {
			return cty.NilType, fmt.Errorf("all arguments must have the same type")
		}
		return ret, nil
	},
	Impl: func(args []cty.Value, retType cty.Type) (cty.Value, error) {
		for _, a := range args {
			a, _ = convert.Convert(a, retType)
			if !a.IsKnown() {
				return cty.UnknownVal(retType), nil
			}
			if a.IsNull() {
				continue
			}
			if retType == cty.String && a.RawEquals(cty.StringVal("")) {
				continue
			}
			return a, nil
		}
		return cty.NilVal, fmt.Errorf("no non-null, non-empty-string arguments")
	},
})

// length: of a string (grapheme clusters), a collection, or a structural type.
var lengthFunc = function.New(&function.Spec{
	Params: []function.Parameter{{Name: "value", Type: cty.DynamicPseudoType, AllowDynamicType: true,
		AllowUnknown: true}},
	Type: func(args []cty.Value) (cty.Type, error) {
		t := args[0].Type()
		if t == cty.String || t.IsTupleType() || t.IsObjectType() || t.IsListType() || t.IsMapType() ||
			t.IsSetType() || t == cty.DynamicPseudoType {
			return cty.Number, nil
		}
		return cty.Number, fmt.Errorf("argument must be a string, a collection type, or a structural type")
	},
	Impl: func(args []cty.Value, retType cty.Type) (cty.Value, error) {
		v, t := args[0], args[0].Type()
		switch {
		case t == cty.DynamicPseudoType:
			return cty.UnknownVal(cty.Number), nil
		case t.IsTupleType():
			return cty.NumberIntVal(int64(len(t.TupleElementTypes()))), nil
		case t.IsObjectType():
			return cty.NumberIntVal(int64(len(t.AttributeTypes()))), nil
		case t == cty.String:
			return stdlib.Strlen(v)
		}
		return v.Length(), nil
	},
})

// lookup: a map element or object attribute, else the default.
var lookupFunc = function.New(&function.Spec{
	Params: []function.Parameter{{Name: "inputMap", Type: cty.DynamicPseudoType, AllowUnknown: true},
		{Name: "key", Type: cty.String, AllowUnknown: true}},
	VarParam: &function.Parameter{Name: "default", Type: cty.DynamicPseudoType, AllowUnknown: true,
		AllowDynamicType: true, AllowNull: true},
	Type: func(args []cty.Value) (cty.Type, error) {
		if len(args) < 1 || len(args) > 3 {
			return cty.NilType, fmt.Errorf("lookup() takes two or three arguments")
		}
		ty := args[0].Type()
		switch {
		case ty.IsObjectType():
			if !args[1].IsKnown() {
				return cty.DynamicPseudoType, nil
			}
			key := args[1].AsString()
			if ty.HasAttribute(key) {
				return args[0].GetAttr(key).Type(), nil
			} else if len(args) == 3 {
				return args[2].Type(), nil
			}
			return cty.DynamicPseudoType, fmt.Errorf("no attribute %q", key)
		case ty.IsMapType():
			if len(args) == 3 {
				if _, err := convert.Convert(args[2], ty.ElementType()); err != nil {
					return cty.NilType, err
				}
			}
			return ty.ElementType(), nil
		}
		return cty.NilType, fmt.Errorf("lookup() requires a map as the first argument")
	},
	Impl: func(args []cty.Value, retType cty.Type) (cty.Value, error) {
		m, k := args[0], args[1]
		if !(m.IsKnown() && k.IsKnown()) {
			return cty.UnknownVal(retType), nil
		}
		key := k.AsString()
		if m.Type().IsObjectType() {
			if m.Type().HasAttribute(key) {
				return m.GetAttr(key), nil
			}
		} else if m.HasIndex(cty.StringVal(key)) == cty.True {
			return m.Index(cty.StringVal(key)), nil
		}
		if len(args) == 3 {
			return convert.Convert(args[2], retType)
		}
		return cty.UnknownVal(cty.DynamicPseudoType), fmt.Errorf("lookup failed to find key %s", key)
	},
})

var unknownFunc = function.New(&function.Spec{
	VarParam: &function.Parameter{Name: "args", Type: cty.DynamicPseudoType, AllowNull: true,
		AllowUnknown: true, AllowDynamicType: true, AllowMarked: true},
	Type: function.StaticReturnType(cty.DynamicPseudoType),
	Impl: func(args []cty.Value, retType cty.Type) (cty.Value, error) { return cty.DynamicVal, nil },
})

type funcs map[string]function.Function

func (f funcs) get(name string) function.Function {
	if fn, ok := f[name]; ok {
		return fn
	}
	return unknownFunc
}

func encode(v cty.Value) any {
	if !v.IsKnown() {
		return map[string]any{"k": "u"}
	}
	if v.IsNull() {
		return map[string]any{"k": "null"}
	}
	t := v.Type()
	switch {
	case t == cty.String:
		return map[string]any{"k": "s", "v": v.AsString()}
	case t == cty.Number:
		return map[string]any{"k": "n", "v": v.AsBigFloat().Text('f', -1)}
	case t == cty.Bool:
		return map[string]any{"k": "b", "v": v.True()}
	case t.IsListType() || t.IsTupleType() || t.IsSetType():
		items := []any{}
		for it := v.ElementIterator(); it.Next(); {
			_, e := it.Element()
			items = append(items, encode(e))
		}
		kind := "l"
		if t.IsSetType() {
			kind = "set"
		}
		return map[string]any{"k": kind, "v": items}
	case t.IsMapType() || t.IsObjectType():
		obj := map[string]any{}
		for it := v.ElementIterator(); it.Next(); {
			k, e := it.Element()
			obj[k.AsString()] = encode(e)
		}
		return map[string]any{"k": "o", "v": obj}
	}
	return map[string]any{"k": "u"}
}

type attr struct {
	file string
	path string
	a    *hclsyntax.Attribute
}

func main() {
	root := os.Args[1]
	fns := funcs{}
	for k, v := range known {
		fns[k] = v
	}
	fns["coalesce"] = coalesceFunc
	fns["length"] = lengthFunc
	fns["lookup"] = lookupFunc
	fns["tostring"] = convFunc(cty.String)
	fns["tonumber"] = convFunc(cty.Number)
	fns["tobool"] = convFunc(cty.Bool)
	fns["tolist"] = convFunc(cty.List(cty.DynamicPseudoType))
	enc := json.NewEncoder(os.Stdout)
	dirs := map[string]bool{}
	filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() && strings.HasSuffix(p, ".tf") && !strings.Contains(p, "/.terraform/") {
			dirs[filepath.Dir(p)] = true
		}
		return nil
	})
	var order []string
	for d := range dirs {
		order = append(order, d)
	}
	sort.Strings(order)
	for _, dir := range order {
		files, _ := filepath.Glob(filepath.Join(dir, "*.tf"))
		sort.Strings(files)
		vars := map[string]cty.Value{}
		decl := map[string]*hclsyntax.Block{}
		locals := map[string]*hclsyntax.Attribute{}
		var attrs []attr
		bodies := map[string]*hclsyntax.Body{}
		for _, f := range files {
			if strings.HasSuffix(f, "override.tf") {
				continue
			}
			src, _ := os.ReadFile(f)
			file, diags := hclsyntax.ParseConfig(src, f, hcl.InitialPos)
			if diags.HasErrors() {
				continue
			}
			rel, _ := filepath.Rel(root, f)
			body := file.Body.(*hclsyntax.Body)
			bodies[rel] = body
			for _, b := range body.Blocks {
				switch b.Type {
				case "variable":
					decl[b.Labels[0]] = b
					if d, ok := b.Body.Attributes["default"]; ok {
						v, diags := d.Expr.Value(nil)
						if !diags.HasErrors() {
							vars[b.Labels[0]] = v
						} else {
							vars[b.Labels[0]] = cty.DynamicVal
						}
					} else {
						vars[b.Labels[0]] = cty.DynamicVal
					}
				case "locals":
					for n, a := range b.Body.Attributes {
						locals[n] = a
						attrs = append(attrs, attr{rel, "locals." + n, a})
					}
				}
			}
		}
		tfvars := []string{filepath.Join(dir, "terraform.tfvars")}
		auto, _ := filepath.Glob(filepath.Join(dir, "*.auto.tfvars"))
		sort.Strings(auto)
		for _, tv := range append(tfvars, auto...) {
			src, err := os.ReadFile(tv)
			if err != nil {
				continue
			}
			file, diags := hclsyntax.ParseConfig(src, tv, hcl.InitialPos)
			if diags.HasErrors() {
				continue
			}
			for n, a := range file.Body.(*hclsyntax.Body).Attributes {
				if _, declared := vars[n]; !declared {
					continue
				}
				v, diags := a.Expr.Value(nil)
				if !diags.HasErrors() {
					vars[n] = v
				}
			}
		}
		for n, b := range decl {
			v := vars[n]
			if !v.IsKnown() {
				continue
			}
			if v.IsNull() {
				if nb, ok := b.Body.Attributes["nullable"]; ok {
					nv, _ := nb.Expr.Value(nil)
					if nv.RawEquals(cty.False) {
						if d, ok := b.Body.Attributes["default"]; ok {
							v, _ = d.Expr.Value(nil)
						}
					}
				}
			}
			if t, ok := b.Body.Attributes["type"]; ok {
				ty, defaults, diags := typeexpr.TypeConstraintWithDefaults(t.Expr)
				if diags.HasErrors() {
					vars[n] = cty.DynamicVal
					continue
				}
				if defaults != nil {
					v = defaults.Apply(v)
				}
				cv, err := convert.Convert(v, ty)
				if err != nil {
					cv = cty.DynamicVal
				}
				v = cv
			}
			vars[n] = v
		}
		ctx := &hcl.EvalContext{Variables: map[string]cty.Value{}, Functions: map[string]function.Function{}}
		// every root name an expression may use: unknown unless var/local
		for _, b := range bodies {
			hclsyntax.VisitAll(b, func(n hclsyntax.Node) hcl.Diagnostics {
				if st, ok := n.(*hclsyntax.ScopeTraversalExpr); ok {
					ctx.Variables[st.Traversal.RootName()] = cty.DynamicVal
				}
				if fc, ok := n.(*hclsyntax.FunctionCallExpr); ok {
					ctx.Functions[fc.Name] = fns.get(fc.Name)
				}
				return nil
			})
		}
		ctx.Variables["var"] = cty.ObjectVal(vars)
		localVals := map[string]cty.Value{}
		for n := range locals {
			localVals[n] = cty.DynamicVal
		}
		for i := 0; i < len(locals)+1; i++ {
			ctx.Variables["local"] = cty.ObjectVal(localVals)
			next := map[string]cty.Value{}
			for n, a := range locals {
				v, diags := a.Expr.Value(ctx)
				if diags.HasErrors() {
					v = cty.DynamicVal
				}
				next[n] = v
			}
			localVals = next
		}
		ctx.Variables["local"] = cty.ObjectVal(localVals)
		var walk func(rel, prefix string, b *hclsyntax.Body)
		walk = func(rel, prefix string, b *hclsyntax.Body) {
			names := []string{}
			for n := range b.Attributes {
				names = append(names, n)
			}
			sort.Strings(names)
			for _, n := range names {
				attrs = append(attrs, attr{rel, prefix + n, b.Attributes[n]})
			}
			counts := map[string]int{}
			for _, blk := range b.Blocks {
				if blk.Type == "dynamic" || blk.Type == "variable" || blk.Type == "locals" {
					continue
				}
				key := blk.Type
				if len(blk.Labels) > 0 && prefix == "" {
					key += "." + strings.Join(blk.Labels, ".")
				}
				walk(rel, prefix+key+"#"+itoa(counts[key])+".", blk.Body)
				counts[key]++
			}
		}
		rels := []string{}
		for r := range bodies {
			rels = append(rels, r)
		}
		sort.Strings(rels)
		for _, r := range rels {
			walk(r, "", bodies[r])
		}
		for _, a := range attrs {
			v, diags := a.a.Expr.Value(ctx)
			out := map[string]any{"file": a.file, "line": a.a.SrcRange.Start.Line, "path": a.path}
			if diags.HasErrors() {
				out["error"] = true
			} else {
				out["value"] = encode(v)
			}
			enc.Encode(out)
		}
	}
}

func itoa(i int) string { return strconv.Itoa(i) }
