package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/pod-security-admission/api"
	"k8s.io/pod-security-admission/policy"
	"sigs.k8s.io/yaml"
)

// For each fixture: every check that denies it, per level, at v1.38.
func main() {
	ev, err := policy.NewEvaluator(policy.DefaultChecks(), nil)
	if err != nil {
		panic(err)
	}
	files, _ := filepath.Glob(filepath.Join(os.Args[1], "*", "v1.38", "*", "*.yaml"))
	sort.Strings(files)
	for _, f := range files {
		data, _ := os.ReadFile(f)
		var pod corev1.Pod
		if err := yaml.UnmarshalStrict(data, &pod); err != nil {
			panic(err)
		}
		for _, level := range []api.Level{api.LevelBaseline, api.LevelRestricted} {
			lv := api.LevelVersion{Level: level, Version: api.MajorMinorVersion(1, 38)}
			var denied []string
			for _, r := range ev.EvaluatePod(lv, &pod.ObjectMeta, &pod.Spec) {
				if !r.Allowed {
					denied = append(denied, r.ForbiddenReason)
				}
			}
			fmt.Printf("%s\t%s\t%s\n", f[len(os.Args[1])+1:], level, strings.Join(denied, "|"))
		}
	}
}
