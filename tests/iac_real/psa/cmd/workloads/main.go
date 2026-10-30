package main

import (
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"k8s.io/apimachinery/pkg/runtime"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/pod-security-admission/admission"
	"k8s.io/pod-security-admission/api"
	"k8s.io/pod-security-admission/policy"
)

// Every workload under a directory: the checks that deny its pod at each level (v1.38).
func main() {
	root := os.Args[1]
	ev, err := policy.NewEvaluator(policy.DefaultChecks(), nil)
	if err != nil {
		panic(err)
	}
	extractor := admission.DefaultPodSpecExtractor{}
	dec := scheme.Codecs.UniversalDeserializer()
	filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !(strings.HasSuffix(p, ".yaml") || strings.HasSuffix(p, ".yml") || strings.HasSuffix(p, ".json")) {
			return nil
		}
		data, _ := os.ReadFile(p)
		r := utilyaml.NewYAMLOrJSONDecoder(bytes.NewReader(data), 4096)
		for {
			var raw runtime.RawExtension
			if err := r.Decode(&raw); err != nil {
				if err != io.EOF {
					fmt.Fprintf(os.Stderr, "%s: %v\n", p, err)
				}
				return nil
			}
			if len(bytes.TrimSpace(raw.Raw)) == 0 {
				continue
			}
			obj, gvk, err := dec.Decode(raw.Raw, nil, nil)
			if err != nil {
				continue
			}
			meta, spec, err := extractor.ExtractPodSpec(obj)
			if err != nil || spec == nil {
				continue
			}
			type named interface{ GetName() string; GetNamespace() string }
			o := obj.(named)
			id := gvk.Kind + "/" + o.GetName()
			if o.GetNamespace() != "" {
				id = gvk.Kind + "/" + o.GetNamespace() + "/" + o.GetName()
			}
			for _, level := range []api.Level{api.LevelBaseline, api.LevelRestricted} {
				lv := api.LevelVersion{Level: level, Version: api.MajorMinorVersion(1, 38)}
				var denied []string
				for _, res := range ev.EvaluatePod(lv, meta, spec) {
					if !res.Allowed {
						denied = append(denied, res.ForbiddenReason)
					}
				}
				rel, _ := filepath.Rel(root, p)
				fmt.Printf("%s\t%s\t%s\t%s\n", rel, id, level, strings.Join(denied, "|"))
			}
		}
	})
}
