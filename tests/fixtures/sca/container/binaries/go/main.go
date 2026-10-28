package main

import (
	"os"

	"gopkg.in/yaml.v2"
)

func main() {
	var v map[string]string
	_ = yaml.Unmarshal([]byte("a: b"), &v)
	os.Stdout.WriteString(v["a"] + "\n")
}
