package org.yaml.snakeyaml;

// A minimal stand-in for SnakeYAML's Yaml class: concrete, constructed with `new`,
// so there is no interface for a proxy to stand in for.
public class Yaml {
    public Object load(String yaml) {
        return yaml;                 // the real load() builds arbitrary types from the document
    }
}
