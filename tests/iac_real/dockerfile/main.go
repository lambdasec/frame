package main

import (
	"encoding/json"
	"os"
	"strings"

	"github.com/moby/buildkit/frontend/dockerfile/parser"
)

type heredoc struct {
	Name    string `json:"name"`
	Content string `json:"content"`
	Chomp   bool   `json:"chomp"`
	Expand  bool   `json:"expand"`
	FD      uint   `json:"fd"`
}

type node struct {
	Cmd      string    `json:"cmd"`
	Args     []string  `json:"args"`
	Flags    []string  `json:"flags"`
	JSON     bool      `json:"json"`
	Start    int       `json:"start"`
	End      int       `json:"end"`
	Heredocs []heredoc `json:"heredocs"`
	Sub      *node     `json:"sub,omitempty"`
}

func dump(n *parser.Node) *node {
	out := &node{Cmd: n.Value, Flags: n.Flags, JSON: n.Attributes["json"], Start: n.StartLine, End: n.EndLine,
		Args: []string{}, Heredocs: []heredoc{}}
	if out.Flags == nil {
		out.Flags = []string{}
	}
	for _, h := range n.Heredocs {
		out.Heredocs = append(out.Heredocs, heredoc{h.Name, h.Content, h.Chomp, h.Expand, h.FileDescriptor})
	}
	for a := n.Next; a != nil; a = a.Next {
		if len(a.Children) > 0 {
			out.Sub = dump(a.Children[0])
			out.Sub.Start, out.Sub.End = 0, 0
			continue
		}
		out.Args = append(out.Args, a.Value)
	}
	return out
}

// One JSON line per file argument: {"file", "escape", "nodes"} or {"file", "error"}.
func main() {
	enc := json.NewEncoder(os.Stdout)
	for _, f := range os.Args[1:] {
		fh, err := os.Open(f)
		if err != nil {
			continue
		}
		res, err := parser.Parse(fh)
		fh.Close()
		if err != nil {
			msg := err.Error()
			enc.Encode(map[string]any{"file": f, "error": strings.SplitN(msg, "\n", 2)[0]})
			continue
		}
		nodes := []*node{}
		for _, c := range res.AST.Children {
			nodes = append(nodes, dump(c))
		}
		enc.Encode(map[string]any{"file": f, "escape": string(res.EscapeToken), "nodes": nodes})
	}
}
