package main

import (
	"encoding/xml"
	"net/url"
	"os"

	"gopkg.in/yaml.v2"
)

type Doc struct{ Name string }

func main() {
	var v map[string]string
	_ = yaml.Unmarshal([]byte("a: b"), &v)
	var d Doc
	_ = xml.NewDecoder(os.Stdin).Decode(&d)
	u, _ := url.Parse(d.Name)
	os.Stdout.WriteString(v["a"] + u.String() + "\n")
}
